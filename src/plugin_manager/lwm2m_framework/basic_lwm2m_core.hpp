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

#ifndef PUNICA_PLUGIN_MANAGER_LWM2M_BASIC_LWM2M_CORE_HPP
#define PUNICA_PLUGIN_MANAGER_LWM2M_BASIC_LWM2M_CORE_HPP

#include <punica/lwm2m_core.hpp>

class BasicLwm2mCore: public Lwm2mCore
{
public:
    BasicLwm2mCore(void *lwm2m_context);
    ~BasicLwm2mCore();

    void *getContext();

private:
    void *context;
};

#endif // PUNICA_PLUGIN_MANAGER_LWM2M_BASIC_LWM2M_CORE_HPP
