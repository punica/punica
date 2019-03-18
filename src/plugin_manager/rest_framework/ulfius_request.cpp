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

std::map<std::string, std::string> ulfiusToStdMap(struct _u_map *ulfiusMap)
{
    int header_iterator;
    std::map<std::string, std::string> stdMap;
    std::string key, value;

    if (ulfiusMap == NULL)
    {
        return stdMap;
    }

    for (header_iterator = 0; ulfiusMap->keys[header_iterator] != NULL; header_iterator++)
    {
        key = ulfiusMap->keys[header_iterator];
        if (ulfiusMap->lengths[header_iterator] > 0)
        {
            value = ulfiusMap->values[header_iterator];
        }
        else
        {
            value = "";
        }
        stdMap.insert(std::make_pair(key, value));
    }

    return stdMap;
}

UlfiusRequest::UlfiusRequest(const struct _u_request *uRequest)
{
    uint8_t *uint_body = (uint8_t *)uRequest->binary_body;
    std::vector<uint8_t> vector_body(uint_body, uint_body + uRequest->binary_body_length);
    std::string tmpPath(uRequest->http_url);
    std::string tmpMethod(uRequest->http_verb);

    mPath = tmpPath;
    mMethod = tmpMethod;
    mHeaders = ulfiusToStdMap(uRequest->map_header);
    mBody = vector_body;
}
UlfiusRequest::~UlfiusRequest() { }
std::string UlfiusRequest::getPath()
{
    return mPath;
}
std::string UlfiusRequest::getMethod()
{
    return mMethod;
}
std::string UlfiusRequest::getHeader(const std::string header)
{
    std::string headerValue;
    std::map<std::string, std::string>::iterator headersIterator;

    headersIterator = mHeaders.find(header);

    if (headersIterator != mHeaders.end())
    {
        headerValue = headersIterator->second;
    }
    return headerValue;
}
std::vector<uint8_t> UlfiusRequest::getBody()
{
    return mBody;
}
