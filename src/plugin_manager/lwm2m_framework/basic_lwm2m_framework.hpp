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

#ifndef BASIC_LWM2M_FRAMEWORK_HPP
#define BASIC_LWM2M_FRAMEWORK_HPP

#include "plugin_manager/lwm2m_framework/lwm2m_framework.hpp"

class BasicLwm2mFramework: public Lwm2mFramework
{
public:
    BasicLwm2mFramework(void *lwm2m_context);
    ~BasicLwm2mFramework();

    void *getContext();

private:
    void *context;
};

#endif // BASIC_LWM2M_FRAMEWORK_HPP
