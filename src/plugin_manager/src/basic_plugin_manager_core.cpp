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

#include "../rest_framework/include/ulfius_rest_framework.hpp"
#include "../lwm2m_framework/include/basic_lwm2m_framework.hpp"
#include "../include/basic_plugin_manager_core.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "../include/basic_plugin_manager_core.h"

CBasicPluginManagerCore *new_BasicPluginManagerCore(struct _u_instance *ulfius_instance,
                                                    void *lwm2m_context)
{
    return reinterpret_cast<CBasicPluginManagerCore *>(new BasicPluginManagerCore(ulfius_instance, lwm2m_context)); 
}
void delete_BasicPluginManagerCore(CBasicPluginManagerCore *c_manager_core)
{
    delete reinterpret_cast<BasicPluginManagerCore *>(c_manager_core);
}
CUlfiusRestFramework *BasicPluginManagerCore_getRestFramework(CBasicPluginManagerCore *c_manager_core)
{
    BasicPluginManagerCore *manager_core = reinterpret_cast<BasicPluginManagerCore *>(c_manager_core);
    RestFramework *rest_framework = manager_core->getRestFramework();

    return reinterpret_cast<CUlfiusRestFramework *>(rest_framework);
}
CBasicLwm2mFramework *BasicPluginManagerCore_getLwm2mFramework(CBasicPluginManagerCore *c_manager_core)
{
    BasicPluginManagerCore *manager_core = reinterpret_cast<BasicPluginManagerCore *>(c_manager_core);
    Lwm2mFramework *lwm2m_framework = manager_core->getLwm2mFramework();

    return reinterpret_cast<CBasicLwm2mFramework *>(lwm2m_framework);
}

#ifdef __cplusplus
} // extern "C"
#endif

BasicPluginManagerCore::BasicPluginManagerCore(struct _u_instance *ulfius_instance, void *rest_context)
{
    restFramework = new UlfiusRestFramework(ulfius_instance);
    lwm2mFramework = new BasicLwm2mFramework(rest_context);
}
BasicPluginManagerCore::~BasicPluginManagerCore()
{
    delete restFramework;
    delete lwm2mFramework;
}
RestFramework *BasicPluginManagerCore::getRestFramework()
{
    return restFramework;
}
Lwm2mFramework *BasicPluginManagerCore::getLwm2mFramework()
{
    return lwm2mFramework;
}
