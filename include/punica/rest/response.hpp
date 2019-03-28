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

#ifndef PUNICA_REST_RESPONSE_HPP
#define PUNICA_REST_RESPONSE_HPP

#include <memory>
#include <string>
#include <vector>

#include <stdint.h>

namespace punica {
namespace rest {

class Response
{
public:
    typedef std::shared_ptr<Response> ptr;

    virtual ~Response() { }

    virtual void setBody(std::vector<uint8_t> binary_data) = 0;
    virtual void setCode(const int code) = 0;
    virtual void setHeader(const std::string header,
                           const std::string value) = 0;
};

} /* namespace rest */
} /* namespace punica */

#endif // PUNICA_REST_RESPONSE_HPP
