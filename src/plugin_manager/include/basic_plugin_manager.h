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

#ifndef BASIC_PLUGIN_MANAGER_H
#define BASIC_PLUGIN_MANAGER_H

#include "basic_plugin_manager_core.h"

enum
{
    J_MAX_LENGTH_PLUGIN_NAME = 1024,
    J_MAX_LENGTH_PLUGIN_PATH = 1024,
};

struct CBasicPluginManager;
typedef struct CBasicPluginManager CBasicPluginManager;

CBasicPluginManager *new_BasicPluginManager(CBasicPluginManagerCore *c_manager_core);
void delete_BasicPluginManager(CBasicPluginManager *c_manager);
int BasicPluginManager_loadPlugin(CBasicPluginManager *c_manager,
                                  const char *c_path,
                                  const char *c_name);
int BasicPluginManager_unloadPlugin(CBasicPluginManager *c_manager,
                                    const char *c_name);

#endif // BASIC_PLUGIN_MANAGER_H
