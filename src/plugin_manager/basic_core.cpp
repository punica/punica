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

basic_punica_core_t *basic_punica_core_new(struct _u_instance *ulfius_instance,
                                           void *lwm2m_context)
{
    return reinterpret_cast<basic_punica_core_t *>(
               new BasicCore(ulfius_instance, lwm2m_context));
}

void basic_punica_core_delete(basic_punica_core_t *core)
{
    delete reinterpret_cast<BasicCore *>(core);
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
