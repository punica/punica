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

#include <vector>
#include <stdint.h>

#include <punica/rest/http_codes.h>

#include "test_plugin_with_counters.hpp"

int destroyCounterCallback(punica::rest::Request::ptr request,
                           punica::rest::Response::ptr response,
                           void *context)
{
    TestPluginWithCounters* plugin =
        reinterpret_cast<TestPluginWithCounters *>(context);
    std::string name = request->getUrlFormat("name");

    if (plugin->destroyCounter(name) == false)
    {
        return HTTP_404_NOT_FOUND;
    }

    return HTTP_204_NO_CONTENT;
}

int createCounterCallback(punica::rest::Request::ptr request,
                          punica::rest::Response::ptr response,
                          void *context)
{
    std::string name;
    TestPluginWithCounters* plugin =
        reinterpret_cast<TestPluginWithCounters *>(context);
    std::vector<uint8_t> requestBody = request->getBody();
    
    requestBody.push_back('\0');
    name = std::string(reinterpret_cast<char *>(requestBody.data()));

    if (plugin->createCounter(name) == false)
    {
        return HTTP_404_NOT_FOUND;
    }

    return HTTP_201_CREATED;
}

TestPluginWithCounters::TestPluginWithCounters(punica::rest::Core::ptr core):
    mRestCore(core)
{
    void *pluginContext = reinterpret_cast<void *>(this);

    mRestCore->addCallbackHandler("POST",
                                  "/test_plugin_with_counters/counter", "", 11,
                                  &createCounterCallback, pluginContext);
    mRestCore->addCallbackHandler("DELETE",
                                  "/test_plugin_with_counters/counter",
                                  ":name", 11,
                                  &destroyCounterCallback, pluginContext);
}

TestPluginWithCounters::~TestPluginWithCounters()
{
    mRestCore->removeCallbackHandler("POST",
                                     "/test_plugin_with_counters/counter", "");
    mRestCore->removeCallbackHandler("DELETE",
                                     "/test_plugin_with_counters/counter", "");
}

bool TestPluginWithCounters::createCounter(std::string name)
{
    destroyCounter(name);
    if (name == "")
    {
        return false;
    }

    Counter::ptr counter(
        new Counter(mRestCore, "/test_plugin_with_counters/counter/", name));
    mCounters[name] = std::move(counter);

    return true;
}

bool TestPluginWithCounters::destroyCounter(std::string name)
{
    Counter::map::iterator iterator = mCounters.find(name);
    if (iterator == mCounters.end())
    {
        return false;
    }

    Counter::ptr counter = std::move(mCounters[name]);
    mCounters.erase(iterator);
    return true;
}

static punica::plugin::Plugin *newTestPlugin(punica::Core::ptr core)
{
    punica::rest::Core::ptr restCore = core->getRestCore();
    TestPluginWithCounters *plugin = new TestPluginWithCounters(restCore);

    return plugin;
}

static void deleteTestPlugin(punica::plugin::Plugin *plugin)
{
    delete static_cast<TestPluginWithCounters *>(plugin);
}
