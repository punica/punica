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

#ifndef PLUGIN_API_HPP
#define PLUGIN_API_HPP

#include "plugin.hpp"
#include "plugin_manager_core.hpp"

#define PLUGIN_HANDLE_NAME "PLUGIN_API"

typedef Plugin * (*plugin_create_t)(PluginManagerCore *core);
typedef void (*plugin_destroy_t)(Plugin *plugin);

typedef struct
{
    uint32_t major:8,
             minor:8,
             revision:16;
} plugin_version_t;

typedef struct
{
    plugin_version_t version;
    plugin_create_t create;
    plugin_destroy_t destroy;
} plugin_api_t;

#endif // PLUGIN_API_HPP
