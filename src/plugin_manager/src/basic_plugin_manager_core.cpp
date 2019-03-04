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
