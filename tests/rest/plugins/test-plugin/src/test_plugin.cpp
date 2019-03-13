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
    return stamp;
}

void TestPlugin::setStamp(std::string new_stamp)
{
    stamp = new_stamp;
}

StatusCode stamp(Request *request, Response *response, void *context)
{
    TestPlugin* plugin = reinterpret_cast<TestPlugin *>(context);
    std::string stamp;
    std::string append_header_value;
    std::string method = request->getMethod();
    std::string string_request_body;
    std::string string_response_body;
    std::vector<uint8_t> request_body;
    std::vector<uint8_t> response_body;
    StatusCode status_code = success_ok;
    
    response->setHeader("Test-status", "success");
  
    if (method == "GET")
    {
        string_response_body = plugin->getStamp();
    }
    else if (method == "PUT")
    {
        request_body = request->getBody();
        request_body.push_back('\0');
        string_request_body = std::string(reinterpret_cast<char *>(request_body.data()));

        plugin->setStamp(string_request_body);

        status_code = success_no_content;
    }
    else if (method == "POST")
    {
        request_body = request->getBody();
        request_body.push_back('\0');
        string_request_body = std::string(reinterpret_cast<char *>(request_body.data()));
        append_header_value = request->getHeader("Append");

        stamp = plugin->getStamp();
        if ((append_header_value == "1")
         || (append_header_value == "yes")
         || (append_header_value == "true"))
        {
            string_response_body = string_request_body + stamp;
        }
        else
        {
            string_response_body = stamp + string_request_body;
        }
    }
    else
    {
        response->setHeader("Test-status", "fail");

        status_code = client_error_method_not_allowed;
    }

    response_body = std::vector<uint8_t>(string_response_body.begin(), string_response_body.end());

    response->setCode(status_code);
    response->setBody(response_body);
    return status_code;
}

static Plugin *NewTestPlugin(Core *core)
{
    TestPlugin *plugin = new TestPlugin("Test Plugin Stamp");
    RestCore *rest_core = core->getRestCore();
    rest_core->addHandler("*", "/test_plugin/stamp", 10, stamp, reinterpret_cast<void *>(plugin));

    return plugin;
}

static void DeleteTestPlugin(Plugin *plugin)
{
    delete static_cast<TestPlugin *>(plugin);
}
