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

#include "test_plugin.hpp"

std::string TestPlugin::getStamp()
{
    return mStamp;
}

void TestPlugin::setStamp(std::string newStamp)
{
    mStamp = newStamp;
}

punica::rest::StatusCode stampCallback(punica::rest::Request *request,
                                       punica::rest::Response *response,
                                       void *context)
{
    TestPlugin* plugin = reinterpret_cast<TestPlugin *>(context);
    std::string stamp;
    std::string appendHeaderValue;
    std::string method = request->getMethod();
    std::string stringRequestBody;
    std::string stringResponseBody;
    std::vector<uint8_t> requestBody;
    std::vector<uint8_t> responseBody;
    punica::rest::StatusCode statusCode = punica::rest::success_ok;
    
    response->setHeader("Test-status", "success");
  
    if (method == "GET")
    {
        stringResponseBody = plugin->getStamp();
    }
    else if (method == "PUT")
    {
        requestBody = request->getBody();
        requestBody.push_back('\0');
        stringRequestBody =
            std::string(reinterpret_cast<char *>(requestBody.data()));

        plugin->setStamp(stringRequestBody);

        statusCode = punica::rest::success_no_content;
    }
    else if (method == "POST")
    {
        requestBody = request->getBody();
        requestBody.push_back('\0');
        stringRequestBody =
            std::string(reinterpret_cast<char *>(requestBody.data()));

        appendHeaderValue = request->getHeader("Append");

        stamp = plugin->getStamp();
        if ((appendHeaderValue == "1")
         || (appendHeaderValue == "yes")
         || (appendHeaderValue == "true"))
        {
            stringResponseBody = stringRequestBody + stamp;
        }
        else
        {
            stringResponseBody = stamp + stringRequestBody;
        }
    }
    else
    {
        response->setHeader("Test-status", "fail");

        statusCode = punica::rest::client_error_method_not_allowed;
    }

    responseBody = std::vector<uint8_t>(stringResponseBody.begin(),
                                        stringResponseBody.end());

    response->setCode(statusCode);
    response->setBody(responseBody);
    return statusCode;
}

static punica::plugin::Plugin *newTestPlugin(punica::Core *core)
{
    TestPlugin *plugin = new TestPlugin("Test Plugin Stamp");
    punica::rest::Core *restCore = core->getRestCore();
    void *pluginContext = reinterpret_cast<void *>(plugin);

    restCore->addCallbackHandler("*", "/test_plugin/stamp", "", 10,
                                 stampCallback, pluginContext);

    return plugin;
}

static void deleteTestPlugin(punica::plugin::Plugin *plugin)
{
    delete static_cast<TestPlugin *>(plugin);
}
