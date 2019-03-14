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

#include "rest_framework/ulfius_rest_core.hpp"
#include "lwm2m_framework/basic_lwm2m_core.hpp"
#include "basic_core.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "basic_core.h"

CBasicCore *new_BasicCore(struct _u_instance *ulfius_instance,
                          void *lwm2m_context)
{
    return reinterpret_cast<CBasicCore *>(new BasicCore(ulfius_instance,
                                                        lwm2m_context));
}
void delete_BasicCore(CBasicCore *c_manager_core)
{
    delete reinterpret_cast<BasicCore *>(c_manager_core);
}
CUlfiusRestCore *BasicCore_getRestCore(CBasicCore
                                       *c_manager_core)
{
    BasicCore *manager_core = reinterpret_cast<BasicCore *>(c_manager_core);
    punica::rest::Core *rest_core = manager_core->getRestCore();

    return reinterpret_cast<CUlfiusRestCore *>(rest_core);
}
CBasicLwm2mCore *BasicCore_getLwm2mCore(CBasicCore
                                        *c_manager_core)
{
    BasicCore *manager_core = reinterpret_cast<BasicCore *>(c_manager_core);
    punica::lwm2m::Core *lwm2m_core = manager_core->getLwm2mCore();

    return reinterpret_cast<CBasicLwm2mCore *>(lwm2m_core);
}

#ifdef __cplusplus
} // extern "C"
#endif

BasicCore::BasicCore(struct _u_instance *ulfius_instance,
                     void *rest_context)
{
    restCore = new UlfiusRestCore(ulfius_instance);
    lwm2mCore = new BasicLwm2mCore(rest_context);
}
BasicCore::~BasicCore()
{
    delete restCore;
    delete lwm2mCore;
}
punica::rest::Core *BasicCore::getRestCore()
{
    return restCore;
}
punica::lwm2m::Core *BasicCore::getLwm2mCore()
{
    return lwm2mCore;
}
