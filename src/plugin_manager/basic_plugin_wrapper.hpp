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

#ifndef PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_WRAPPER_HPP
#define PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_WRAPPER_HPP

#include <map>
#include <memory>

#include <punica/core.hpp>
#include <punica/plugin/plugin.hpp>
#include <punica/plugin/plugin_api.hpp>

class BasicPluginWrapper
{
public:
    typedef std::unique_ptr<BasicPluginWrapper> ptr;
    typedef std::map<std::string, BasicPluginWrapper::ptr> map;

    BasicPluginWrapper(std::string path,
                       std::string name);
    ~BasicPluginWrapper();

    bool loadPlugin(punica::Core *core);
    bool unloadPlugin();

private:
    void *mDLL;
    std::string mPath, mName;
    const char *mCName;
    punica::plugin::Plugin *mPlugin;
    punica::plugin::PluginApi *mPluginApi;

    bool loadDLL();
    bool unloadDLL();
    bool loadPluginApi();
};

#endif /* PUNICA_PLUGIN_MANAGER_BASIC_PLUGIN_WRAPPER_HPP */
