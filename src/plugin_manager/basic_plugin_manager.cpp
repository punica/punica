/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2019 8devices
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "basic_plugin_manager.hpp"
#include "basic_plugin_manager.h"

#include "../logging.h"
#include "basic_core.hpp"

static const char *loggingSection = "[PLUGINS]";

basic_plugin_manager_t *basic_plugin_manager_new(basic_punica_core_t *core)
{
    return reinterpret_cast<basic_plugin_manager_t *>(
               new BasicPluginManager(reinterpret_cast<BasicCore &>(*core)));
}

void basic_plugin_manager_delete(basic_plugin_manager_t *c_manager)
{
    delete reinterpret_cast<BasicPluginManager *>(c_manager);
}

int basic_plugin_manager_load_plugin(basic_plugin_manager_t *c_manager,
                                     const char *path,
                                     const char *name)
{
    BasicPluginManager *manager =
        reinterpret_cast<BasicPluginManager *>(c_manager);

    return static_cast<int>(manager->loadPlugin(path, name));
}

int basic_plugin_manager_unload_plugin(basic_plugin_manager_t *c_manager,
                                       const char *name)
{
    BasicPluginManager *manager =
        reinterpret_cast<BasicPluginManager *>(c_manager);

    return static_cast<int>(manager->unloadPlugin(name));
}

int basic_plugin_manager_load_plugins(basic_plugin_manager_t *plugin_manager,
                                      plugins_settings_t *plugins_settings)
{
    linked_list_entry_t *entry;
    plugin_settings_t *plugin;
    int plugins_loaded = 0;

    for (entry = plugins_settings->plugins_list->head;
         entry != NULL; entry = entry->next)
    {
        plugin = (plugin_settings_t *) entry->data;
        if (basic_plugin_manager_load_plugin(plugin_manager,
                                             plugin->path,
                                             plugin->name))
        {
            ++plugins_loaded;
        }
    }

    return plugins_loaded;
}

static void plugin_entry_settings_free(plugin_settings_t *plugin)
{
    free((void *) plugin->path);
    free((void *) plugin->name);
    free(plugin);
}

int basic_plugin_manager_unload_plugins(basic_plugin_manager_t *plugin_manager,
                                        plugins_settings_t *plugins_settings)
{
    linked_list_entry_t *entry;
    plugin_settings_t *plugin;
    int plugins_unloaded = 0;

    for (entry = plugins_settings->plugins_list->head;
         entry != NULL; entry = entry->next)
    {
        plugin = (plugin_settings_t *) entry->data;
        if (basic_plugin_manager_unload_plugin(plugin_manager,
                                               plugin->name))
        {
            ++plugins_unloaded;
        }
        plugin_entry_settings_free(plugin);
    }
    linked_list_delete(plugins_settings->plugins_list);

    return plugins_unloaded;
}

BasicPluginManager::BasicPluginManager(punica::Core &core):
    mCore(core),
    mPlugins()
{
}

BasicPluginManager::~BasicPluginManager()
{
    mPlugins.clear();
}

bool BasicPluginManager::loadPlugin(std::string path, std::string name)
{
    if (mPlugins.find(name) != mPlugins.end())
    {
        log_message(LOG_LEVEL_WARN,
                    "%s Skipping plugin \"%s\" loading!\n",
                    loggingSection, name.c_str());
        log_message(LOG_LEVEL_INFO,
                    "\tPlugin with duplicate name found!\n");
    }

    BasicPluginWrapper::ptr plugin(new BasicPluginWrapper(path, name));
    if (plugin->loadPlugin(mCore) != true)
    {
        return false;
    }

    mPlugins[name] = std::move(plugin);

    return true;
}

bool BasicPluginManager::unloadPlugin(std::string name)
{
    BasicPluginWrapper::map::iterator pluginsIterator = mPlugins.find(name);

    if (pluginsIterator == mPlugins.end())
    {
        return false;
    }

    mPlugins.erase(pluginsIterator);
    return true;
}
