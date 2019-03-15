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

#include <cstring>

#include "ulfius_request.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
} // extern "C"
#endif

std::map<std::string, std::string> ulfiusToStdMap(struct _u_map *ulfius_map)
{
    int header_iterator;
    std::map<std::string, std::string> std_map;
    std::string key, value;

    if (ulfius_map == NULL)
    {
        return std_map;
    }

    for (header_iterator = 0; ulfius_map->keys[header_iterator] != NULL; header_iterator++)
    {
        key = ulfius_map->keys[header_iterator];
        if (ulfius_map->lengths[header_iterator] > 0)
        {
            value = ulfius_map->values[header_iterator];
        }
        else
        {
            value = "";
        }
        std_map.insert(std::make_pair(key, value));
    }

    return std_map;
}

UlfiusRequest::UlfiusRequest(const struct _u_request *u_request)
{
    uint8_t *uint_body = (uint8_t *)u_request->binary_body;
    std::vector<uint8_t> vector_body(uint_body, uint_body + u_request->binary_body_length);
    std::string tmp_path(u_request->http_url);
    std::string tmp_method(u_request->http_verb);

    path = tmp_path;
    method = tmp_method;
    headers = ulfiusToStdMap(u_request->map_header);
    body = vector_body;
}
UlfiusRequest::~UlfiusRequest() { }
std::string UlfiusRequest::getPath()
{
    return path;
}
std::string UlfiusRequest::getMethod()
{
    return method;
}
std::string UlfiusRequest::getHeader(const std::string header)
{
    std::string header_value;
    std::map<std::string, std::string>::iterator headers_iterator;

    headers_iterator = headers.find(header);

    if (headers_iterator != headers.end())
    {
        header_value = headers_iterator->second;
    }
    return header_value;
}
std::vector<uint8_t> UlfiusRequest::getBody()
{
    return body;
}
