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

#ifndef PUNICA_PLUGIN_MANAGER_BASIC_CORE_HPP
#define PUNICA_PLUGIN_MANAGER_BASIC_CORE_HPP

#include <punica/core.hpp>

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
} // extern "C"
#endif

class BasicCore: public punica::Core
{
public:
    BasicCore(struct _u_instance *ulfius_instance,
              void *rest_context);
    ~BasicCore();
    punica::rest::Core *getRestCore();
    punica::lwm2m::Core *getLwm2mCore();

private:
    punica::rest::Core *restCore;
    punica::lwm2m::Core *lwm2mCore;
};

#endif // PUNICA_PLUGIN_MANAGER_BASIC_CORE_HPP
