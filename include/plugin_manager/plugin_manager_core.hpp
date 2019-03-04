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

#ifndef PLUGIN_MANAGER_CORE_HPP
#define PLUGIN_MANAGER_CORE_HPP

#include "../rest_framework/include/rest_framework.hpp"
#include "../lwm2m_framework/include/lwm2m_framework.hpp"

class PluginManagerCore
{
public:
    virtual ~PluginManagerCore() { }

    virtual RestFramework *getRestFramework() = 0;
    virtual Lwm2mFramework *getLwm2mFramework() = 0;

protected:
    RestFramework *restFramework;
    Lwm2mFramework *lwm2mFramework;
};

#endif // PLUGIN_MANAGER_CORE_HPP
