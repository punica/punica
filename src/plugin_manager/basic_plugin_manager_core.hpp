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

#ifndef BASIC_PLUGIN_MANAGER_CORE_HPP
#define BASIC_PLUGIN_MANAGER_CORE_HPP

#include "plugin_manager/plugin_manager_core.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
} // extern "C"
#endif

class BasicPluginManagerCore: public PluginManagerCore
{
public:
    BasicPluginManagerCore(struct _u_instance *ulfius_instance, void *rest_context);
    ~BasicPluginManagerCore();
    RestFramework *getRestFramework();
    Lwm2mFramework *getLwm2mFramework();

private:
    RestFramework *restFramework;
    Lwm2mFramework *lwm2mFramework;
};

#endif // BASIC_PLUGIN_MANAGER_CORE_HPP
