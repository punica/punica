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

#include "basic_lwm2m_core.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include "basic_lwm2m_core.h"

CBasicLwm2mCore *new_BasicLwm2mCore(void *lwm2m_context)
{
    return reinterpret_cast<CBasicLwm2mCore *>(new BasicLwm2mCore(lwm2m_context));
}
void delete_BasicLwm2mCore(CBasicLwm2mCore *c_lwm2m_core)
{
    delete reinterpret_cast<BasicLwm2mCore *>(c_lwm2m_core);
}

#ifdef __cplusplus
} // extern "C"
#endif

BasicLwm2mCore::BasicLwm2mCore(void *lwm2m_context):
    context(lwm2m_context) { }
BasicLwm2mCore::~BasicLwm2mCore()
{ }
void *BasicLwm2mCore::getContext()
{
    return context;
}
