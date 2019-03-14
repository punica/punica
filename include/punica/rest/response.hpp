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

#include <map>
#include <string>
#include <vector>

#include <stdint.h>

namespace punica {
namespace rest {

enum StatusCode
{
    unknown = 0,
    information_continue = 100,
    success_ok = 200,
    success_created = 201,
    success_accepted = 202,
    success_no_content = 204,
    success_reset_content = 205,
    client_error = 400,
    client_error_unauthorized = 401,
    client_error_forbidden = 403,
    client_error_not_found = 404,
    client_error_method_not_allowed = 405,
    client_error_not_acceptable = 406,
    server_error_internal_server_error = 500
};

class Response
{
public:
    virtual ~Response() { }

    virtual void setBody(std::vector<uint8_t> binary_data) = 0;
    virtual void setCode(StatusCode code) = 0;
    virtual void setHeader(const std::string header,
                           const std::string value) = 0;
};

}
} /* namespace punica::rest */

#endif // PUNICA_REST_RESPONSE_HPP
