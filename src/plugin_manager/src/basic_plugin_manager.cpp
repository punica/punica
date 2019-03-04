/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <dlfcn.h>
#include <iostream>

#include "../include/basic_plugin_manager_core.hpp"
#include "../include/basic_plugin_manager.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "../include/basic_plugin_manager.h"

CBasicPluginManager *new_BasicPluginManager(CBasicPluginManagerCore *c_manager_core)
{
    BasicPluginManagerCore *manager_core = reinterpret_cast<BasicPluginManagerCore *>(c_manager_core);

    return reinterpret_cast<CBasicPluginManager *>(new BasicPluginManager(manager_core)); 
}
void delete_BasicPluginManager(CBasicPluginManager *c_manager)
{
    delete reinterpret_cast<BasicPluginManager *>(c_manager);
}
int BasicPluginManager_loadPlugin(CBasicPluginManager *c_manager,
                                  const char *c_path,
                                  const char *c_name)
{
    BasicPluginManager *manager = reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string path(c_path);
    const std::string name(c_name);

    return static_cast<int>(manager->loadPlugin(path, name));
}
int BasicPluginManager_unloadPlugin(CBasicPluginManager *c_manager,
                                    const char *c_name)
{
    BasicPluginManager *manager = reinterpret_cast<BasicPluginManager *>(c_manager);
    const std::string name(c_name);

    return static_cast<int>(manager->unloadPlugin(name));
}

#ifdef __cplusplus
} // extern "C"
#endif

BasicPluginManager::BasicPluginManager(PluginManagerCore *plugin_core):
    core(plugin_core),
    plugins()
{
}
BasicPluginManager::~BasicPluginManager()
{
    std::map<std::string, std::pair<Plugin *, plugin_api_t *> >::iterator plugins_iterator;

    for (plugins_iterator = plugins.begin(); plugins_iterator != plugins.end(); ++plugins_iterator)
    {
        unloadPlugin(plugins_iterator->first);
    }
}
bool BasicPluginManager::loadPlugin(std::string path, std::string name)
{
    if (plugins.find(name) != plugins.end())
    {
        if (unloadPlugin(name) != true)
        {
            return false;
        }
    }

    void *dll = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (dll == NULL)
    {
        std::cerr << "Failed to load plugin file from '" << path << "\"!" << std::endl;
        return false;
    }

    plugin_api_t *plugin_api = static_cast<plugin_api_t *>(dlsym(dll, PLUGIN_HANDLE_NAME));

    if (plugin_api == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        return false;
    }

    if (plugin_api->create == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        std::cerr << "Missing PLUGIN_API->create()" << std::endl;
        return false;
    }
    if (plugin_api->destroy == NULL)
    {
        std::cerr << "Failed to load plugin api from '" << path << "\"!" << std::endl;
        std::cerr << "Missing PLUGIN_API->destroy()" << std::endl;
        return false;
    }

    plugin_version_t plugin_version = plugin_api->version;
    Plugin *plugin = plugin_api->create(core);

    if (plugin == NULL)
    {
        std::cerr << "Failed to create plugin instance!" << std::endl;
        return false;
    }

    plugins[name] = std::make_pair(plugin, plugin_api);

    return true;
}
bool BasicPluginManager::unloadPlugin(std::string name)
{
    std::map<std::string, std::pair<Plugin *, plugin_api_t *> >::iterator plugins_iterator = plugins.find(name);
    Plugin *plugin;
    plugin_api_t *plugin_api;

    if (plugins_iterator == plugins.end())
    {
        return false;
    }

    plugin = plugins_iterator->second.first;
    plugin_api = plugins_iterator->second.second;

    plugin_api->destroy(plugin);

    plugins.erase(plugins_iterator);

    return true;
}
