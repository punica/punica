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
#include <iostream>

#include "ulfius_response.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#ifdef __cplusplus
} // extern "C"
#endif

UlfiusResponse::UlfiusResponse(struct _u_response *uResponse):
    mUlfiusResponse(uResponse) { }

UlfiusResponse::~UlfiusResponse() { }

void UlfiusResponse::setBody(std::vector<uint8_t> binaryData)
{
    if (mUlfiusResponse->binary_body != NULL)
    {
        free(mUlfiusResponse->binary_body);
    }

    mUlfiusResponse->binary_body = malloc(binaryData.size());
    if (mUlfiusResponse->binary_body != NULL)
    {
        mUlfiusResponse->binary_body_length = binaryData.size();
        std::memcpy(mUlfiusResponse->binary_body, binaryData.data(), binaryData.size());
    }
    else
    {
        std::cerr << "Failed to allocate outgoing message body" << std::endl;
    }
}

void UlfiusResponse::setCode(punica::rest::StatusCode code)
{
    mUlfiusResponse->status = static_cast<int>(code);
}

void UlfiusResponse::setHeader(const std::string header, const std::string value)
{
    const char *cHeader = header.c_str();
    const char *cValue = value.c_str();

    u_map_put(mUlfiusResponse->map_header, cHeader, cValue);
}
