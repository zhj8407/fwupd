#!/usr/bin/python3
# pylint: disable=invalid-name,missing-docstring
#
# Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
#
# SPDX-License-Identifier: LGPL-2.1+

import sys
import argparse
import xml.etree.ElementTree as ET

XMLNS = "{http://www.gtk.org/introspection/core/1.0}"
XMLNS_C = "{http://www.gtk.org/introspection/c/1.0}"


def parse_version(ver):
    return tuple(map(int, ver.split(".")))


def usage(return_code):
    """print usage and exit with the supplied return code"""
    if return_code == 0:
        out = sys.stdout
    else:
        out = sys.stderr
    out.write(f"usage: {sys.argv[0]} <NAME> <INPUT> <OUTPUT>\n")
    sys.exit(return_code)


class LdVersionScript:
    """Rasterize some text"""

    def __init__(self, library_name):
        self.library_name = library_name
        self.releases = {}
        self.overrides = {}

    def _add_node(self, node):
        identifier = node.attrib[XMLNS_C + "identifier"]
        introspectable = int(node.get("introspectable", 1))
        version = node.get("version", None)
        if introspectable and not version:
            print("No version for", identifier)
            sys.exit(1)
        if not version:
            return None
        version = node.attrib["version"]
        if version not in self.releases:
            self.releases[version] = []
        release = self.releases[version]
        if identifier not in release:
            release.append(identifier)
        return version

    def _add_cls(self, cls):
        # add all class functions
        for node in cls.findall(XMLNS + "function"):
            self._add_node(node)

        # choose the lowest version method for the _get_type symbol
        version_lowest = None

        # add all class methods
        for node in cls.findall(XMLNS + "method"):
            version_tmp = self._add_node(node)
            if version_tmp:
                if not version_lowest or parse_version(version_tmp) < parse_version(
                    version_lowest
                ):
                    version_lowest = version_tmp

        # add the constructor
        for node in cls.findall(XMLNS + "constructor"):
            version_tmp = self._add_node(node)
            if version_tmp:
                if not version_lowest or parse_version(version_tmp) < parse_version(
                    version_lowest
                ):
                    version_lowest = version_tmp

        if "{http://www.gtk.org/introspection/glib/1.0}get-type" not in cls.attrib:
            return
        type_name = cls.attrib["{http://www.gtk.org/introspection/glib/1.0}get-type"]

        # finally add the get_type symbol
        version = self.overrides.get(type_name, version_lowest)
        if version:
            self.releases[version].append(type_name)

    def import_gir(self, filename):
        tree = ET.parse(filename)
        root = tree.getroot()
        for ns in root.findall(XMLNS + "namespace"):
            for node in ns.findall(XMLNS + "function"):
                self._add_node(node)
            for cls in ns.findall(XMLNS + "record"):
                self._add_cls(cls)
            for cls in ns.findall(XMLNS + "class"):
                self._add_cls(cls)

    def render(self):
        # get a sorted list of all the versions
        versions = []
        for version in self.releases:
            versions.append(version)

        # output the version data to a file
        verout = "# generated automatically, do not edit!\n"
        oldversion = None
        for version in sorted(versions, key=parse_version):
            symbols = sorted(self.releases[version])
            verout += "\n%s_%s {\n" % (self.library_name, version)
            verout += "  global:\n"
            for symbol in symbols:
                verout += f"    {symbol};\n"
            verout += "  local: *;\n"
            if oldversion:
                verout += "} %s_%s;\n" % (self.library_name, oldversion)
            else:
                verout += "};\n"
            oldversion = version
        return verout


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-r", "--override", action="append", nargs=2, metavar=("symbol", "version")
    )
    args, argv = parser.parse_known_args()
    if len(argv) != 3:
        usage(1)

    ld = LdVersionScript(library_name=argv[0])
    if args.override:
        for override_symbol, override_version in args.override:
            ld.overrides[override_symbol] = override_version
    ld.import_gir(argv[1])
    open(argv[2], "w").write(ld.render())
