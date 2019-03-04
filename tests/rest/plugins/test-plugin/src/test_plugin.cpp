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

#include <vector>
#include <stdint.h>

#include "../include/test_plugin.hpp"

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

static Plugin *NewTestPlugin(PluginManagerCore *core)
{
    TestPlugin *plugin = new TestPlugin("Test Plugin Stamp");
    RestFramework *rest_framework = core->getRestFramework();
    rest_framework->addHandler("*", "/test_plugin/stamp", 10, stamp, reinterpret_cast<void *>(plugin));

    return plugin;
}

static void DeleteTestPlugin(Plugin *plugin)
{
    delete static_cast<TestPlugin *>(plugin);
}
