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

#ifndef ULFIUS_REQUEST_HPP
#define ULFIUS_REQUEST_HPP

#include "request.hpp"

class UlfiusRequest: public Request
{
public:
    UlfiusRequest(const struct _u_request *u_request);
    ~UlfiusRequest();

    std::string getPath();
    std::string getMethod();
    std::string getHeader(const std::string header);
    std::vector<uint8_t> getBody();

private:
    std::string path;
    std::string method;
    std::map<std::string, std::string> headers;
    std::vector<uint8_t> body;
};

#endif // ULFIUS_REQUEST_HPP
