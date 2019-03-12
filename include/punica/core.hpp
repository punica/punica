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

#ifndef PUNICA_CORE_HPP
#define PUNICA_CORE_HPP

#include <punica/rest/rest_core.hpp>
#include <punica/lwm2m_core.hpp>

class Core
{
public:
    virtual ~Core() { }

    virtual RestCore *getRestCore() = 0;
    virtual Lwm2mCore *getLwm2mCore() = 0;

protected:
    RestCore *restCore;
    Lwm2mCore *lwm2mCore;
};

#endif // PUNICA_CORE_HPP
