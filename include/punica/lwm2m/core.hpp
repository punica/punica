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

#ifndef PUNICA_LWM2M_CORE_HPP
#define PUNICA_LWM2M_CORE_HPP

#include <memory>

namespace punica {
namespace lwm2m {

class Core
{
public:
    typedef std::shared_ptr<Core> ptr;

    virtual ~Core() { }
};

} /* namespace lwm2m */
} /* namespace punica */

#endif // PUNICA_LWM2M_CORE_HPP
