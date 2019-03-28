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

#include <dlfcn.h>
#include <iostream>

#include "basic_plugin_wrapper.hpp"

BasicPluginWrapper::BasicPluginWrapper(std::string path, std::string name):
    mDLL(nullptr),
    mPath(path),
    mName(name),
    mPlugin(nullptr),
    mPluginApi(nullptr)
{
    loadDLL();
}

BasicPluginWrapper::~BasicPluginWrapper()
{
    if (mPlugin != NULL)
    {
        unloadPlugin();
    }
    unloadDLL();
}

bool BasicPluginWrapper::loadDLL()
{
    if (mDLL != NULL)
    {
        unloadDLL();
    }

    mDLL = dlopen(mPath.c_str(), RTLD_NOW | RTLD_LOCAL);

    if (mDLL == NULL)
    {
        std::cerr << dlerror() << std::endl;
        return false;
    }
    dlerror(); /* Clear any existing error */

    return true;
}

bool BasicPluginWrapper::unloadDLL()
{
    if (mDLL == NULL)
    {
        return false;
    }

    dlclose(mDLL);
    dlerror(); /* Clear any existing error */

    return true;
}

bool BasicPluginWrapper::loadPluginApi()
{
    if (mDLL == NULL)
    {
        return false;
    }

    mPluginApi = static_cast<punica::plugin::PluginApi *>(
                     dlsym(mDLL, PLUGIN_API_HANDLE_NAME));

    if (mPluginApi == NULL)
    {
        std::cerr << "Failed to load plugin from '" << mPath << "\"!";
        std::cerr << dlerror() << std::endl;
        return false;
    }
    dlerror(); /* Clear any existing error */

    if (mPluginApi->create == NULL)
    {
        std::cerr << "Failed to load plugin from '" << mPath << "\"!";
        std::cerr << std::endl << "PLUGIN_API.create is NULL" << std::endl;
        return false;
    }
    if (mPluginApi->destroy == NULL)
    {
        std::cerr << "Failed to load plugin from '" << mPath << "\"!";
        std::cerr << std::endl << "PLUGIN_API.destroy is NULL" << std::endl;
        return false;
    }

    return true;
}

bool BasicPluginWrapper::loadPlugin(punica::Core::ptr core)
{
    if (((mPluginApi == NULL)
         || (mPluginApi->create == NULL))
        && (loadPluginApi() != true))
    {
        return false;
    }

    mPlugin = mPluginApi->create(core);
    if (mPlugin == NULL)
    {
        std::cerr << "Failed to load plugin from '" << mPath << "\"!";
        std::cerr << std::endl << "PLUGIN_API->create() is NULL" << std::endl;
        return false;
    }
    return true;
}

bool BasicPluginWrapper::unloadPlugin()
{
    if ((mPlugin == NULL)
        || (mPluginApi == NULL)
        || (mPluginApi->destroy == NULL))
    {
        return false;
    }

    mPluginApi->destroy(mPlugin);
    return true;
}
