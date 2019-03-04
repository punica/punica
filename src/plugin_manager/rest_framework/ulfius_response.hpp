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

#ifndef ULFIUS_RESPONSE_HPP
#define ULFIUS_RESPONSE_HPP

#include "plugin_manager/rest_framework/response.hpp"

class UlfiusResponse: public Response
{
public:
    UlfiusResponse(struct _u_response *u_response);
    ~UlfiusResponse();

    void setBody(std::vector<uint8_t> binary_data);
    void setCode(const StatusCode code);
    void setHeader(const std::string header, const std::string value);

private:
    struct _u_response *ulfius_response;
};

#endif // ULFIUS_RESPONSE_HPP
