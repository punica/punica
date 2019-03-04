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

#ifndef BASIC_PLUGIN_MANAGER_CORE_H
#define BASIC_PLUGIN_MANAGER_CORE_H

#include "ulfius.h"

#include "../rest_framework/include/ulfius_rest_framework.h"
#include "../lwm2m_framework/include/basic_lwm2m_framework.h"

struct CBasicPluginManagerCore;
typedef struct CBasicPluginManagerCore CBasicPluginManagerCore;

CBasicPluginManagerCore *new_BasicPluginManagerCore(struct _u_instance *ulfius_instance,
                                                    void *lwm2m_context);
void delete_BasicPluginManagerCore(CBasicPluginManagerCore *c_manager_core);
CUlfiusRestFramework *BasicPluginManagerCore_getRestFramework(CBasicPluginManagerCore *c_manager_core);
CBasicLwm2mFramework *BasicPluginManagerCore_getLwm2mFramework(CBasicPluginManagerCore *c_manager_core);

#endif // BASIC_PLUGIN_MANAGER_CORE_H
