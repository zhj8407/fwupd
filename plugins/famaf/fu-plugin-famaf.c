#include "config.h"

#include <fwupdplugin.h>

void
fu_plugin_init (FuPlugin *plugin)
{
	fu_plugin_set_build_hash (plugin, FU_BUILD_HASH);
	g_debug ("init");
}
