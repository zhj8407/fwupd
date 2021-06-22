#include "config.h"

#include <fwupdplugin.h>

void
fu_plugin_init (FuPlugin *plugin)
{
	fu_plugin_set_build_hash (plugin, FU_BUILD_HASH);
	g_debug ("init");
}

gboolean
fu_plugin_coldplug (FuPlugin *plugin, GError **error)
{
	g_autoptr(FuDevice) dev = fu_device_new ();
	g_debug ("coldplug");
	fu_device_set_name (dev, "Hello World");
	fu_device_set_physical_id (dev, "/dev/usb/foobarbaz");
	fu_device_add_vendor_id (dev, "USB:1234");
	fu_device_add_protocol (dev, "org.uefi.capsule");
	fu_device_add_flag (dev, FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_add_instance_id (dev, "USB:VID=1234,PID=4567");
	if (!fu_device_setup (dev, error))
		return FALSE;
	fu_plugin_device_add (plugin, dev);
	return TRUE;
}
