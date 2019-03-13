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

#ifndef PUNICA_PLUGIN_MANAGER_BASIC_CORE_H
#define PUNICA_PLUGIN_MANAGER_BASIC_CORE_H

#include "ulfius.h"

#include "rest_framework/ulfius_rest_core.h"
#include "lwm2m_framework/basic_lwm2m_core.h"

struct CBasicCore;
typedef struct CBasicCore CBasicCore;

CBasicCore *new_BasicCore(struct _u_instance *ulfius_instance,
                          void *lwm2m_context);
void delete_BasicCore(CBasicCore *c_manager_core);
CUlfiusRestCore *BasicCore_getRestCore(CBasicCore
                                       *c_manager_core);
CBasicLwm2mCore *BasicCore_getLwm2mCore(CBasicCore
                                        *c_manager_core);

#endif // PUNICA_PLUGIN_MANAGER_BASIC_CORE_H
