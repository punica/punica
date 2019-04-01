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

#include <cstring>
#include <dlfcn.h>
#include <string.h>

#include <punica/version.h>

#include "basic_plugin_wrapper.hpp"

#include "../logging.h"

static const char loggingSection[] = "[PLUGINS]";

BasicPluginWrapper::BasicPluginWrapper(std::string path,
                                       std::string name):
    mDLL(nullptr),
    mPath(path),
    mName(name),
    mCName(strdup(name.c_str())),
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
        log_message(LOG_LEVEL_ERROR,
                    "%s Failed to load plugin \"%s\" DLL.\n\t%s\n",
                    loggingSection, mCName, dlerror());
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
    const char *pluginApiError, *punicaVersion = PUNICA_VERSION;
    if (mDLL == NULL)
    {
        return false;
    }

    mPluginApi = static_cast<punica::plugin::PluginApi *>(
                     dlsym(mDLL, PLUGIN_API_HANDLE_NAME));

    if (mPluginApi == NULL)
    {
        log_message(LOG_LEVEL_ERROR,
                    "%s Failed to load plugin \"%s\" API.\n\t%s\n",
                    loggingSection, mCName, dlerror());
        return false;
    }
    dlerror(); /* Clear any existing error */

    if (mPluginApi->create == NULL)
    {
        pluginApiError = "PLUGIN_API.create is NULL!";
    }
    else if (mPluginApi->destroy == NULL)
    {
        pluginApiError = "PLUGIN_API.destroy is NULL!";
    }
    else if (mPluginApi->version == NULL)
    {
        pluginApiError = "PLUGIN_API.version is NULL!";
    }
    else if (strcmp(mPluginApi->version, punicaVersion) != 0)
    {
        pluginApiError = "Punica and PLUGIN_API.version mismatch!";
    }
    else
    {
        log_message(LOG_LEVEL_TRACE,
                    "\t Successfully loaded plugin \"%s\" API.\n",
                    loggingSection, mCName);
        return true;
    }

    log_message(LOG_LEVEL_ERROR,
                "%s Failed to load plugin \"%s\" API.\n%s\n",
                loggingSection, mCName, pluginApiError);
    return false;
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
        log_message(LOG_LEVEL_ERROR,
                    "%s Failed to load plugin \"%s\".\n\t%s\n",
                    loggingSection, mCName,
                    "PLUGIN_API.create() returned NULL");

        return false;
    }

    log_message(LOG_LEVEL_INFO,
                "\t Successfully loaded plugin \"%s\".\n",
                loggingSection, mCName);
    return true;
}

bool BasicPluginWrapper::unloadPlugin()
{
    if ((mPlugin == NULL)
        || (mPluginApi == NULL)
        || (mPluginApi->destroy == NULL))
    {
        log_message(LOG_LEVEL_WARN,
                    "\t Failed to unload plugin \"%s\".\n",
                    loggingSection, mCName);
        return false;
    }

    mPluginApi->destroy(mPlugin);
    log_message(LOG_LEVEL_INFO,
                "\t Successfully unloaded plugin \"%s\".\n",
                loggingSection, mCName);
    return true;
}
