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

#include <string>

#include "../../../../../src/plugin_manager/include/plugin.hpp"
#include "../../../../../src/plugin_manager/include/plugin_api.hpp"
#include "../../../../../src/plugin_manager/include/plugin_manager_core.hpp"

class PluginWithoutCreate: public Plugin
{
public:
    PluginWithoutCreate() { }
    ~PluginWithoutCreate() { }
};

static Plugin *NewPluginWithoutCreate(PluginManagerCore *core);
static void DeletePluginWithoutCreate(Plugin *plugin);

extern "C" const plugin_api_t PLUGIN_API =
{
    .version = { 0, 0, 0},
    .create = NULL,
    .destroy = DeletePluginWithoutCreate,
};
