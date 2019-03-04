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

#ifndef BASIC_PLUGIN_MANAGER_CORE_H
#define BASIC_PLUGIN_MANAGER_CORE_H

#include "ulfius.h"

#include "./rest_framework/ulfius_rest_framework.h"
#include "./lwm2m_framework/basic_lwm2m_framework.h"

struct CBasicPluginManagerCore;
typedef struct CBasicPluginManagerCore CBasicPluginManagerCore;

CBasicPluginManagerCore *new_BasicPluginManagerCore(struct _u_instance *ulfius_instance,
                                                    void *lwm2m_context);
void delete_BasicPluginManagerCore(CBasicPluginManagerCore *c_manager_core);
CUlfiusRestFramework *BasicPluginManagerCore_getRestFramework(CBasicPluginManagerCore *c_manager_core);
CBasicLwm2mFramework *BasicPluginManagerCore_getLwm2mFramework(CBasicPluginManagerCore *c_manager_core);

#endif // BASIC_PLUGIN_MANAGER_CORE_H
