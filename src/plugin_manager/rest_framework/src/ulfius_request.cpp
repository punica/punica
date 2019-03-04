/*
 * MIT License
 *
 * Copyright (c) 2018 8devices
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <cstring>

#include "../include/ulfius_request.hpp"

#ifdef __cplusplus
extern "C" {
#endif

#include <ulfius.h>

#include "../include/ulfius_request.h"

CUlfiusRequest *new_UlfiusRequest(const struct _u_request *u_request)
{
    return reinterpret_cast<CUlfiusRequest *>(new UlfiusRequest(u_request));
}
void delete_UlfiusRequest(CUlfiusRequest *c_request)
{
    delete reinterpret_cast<UlfiusRequest *>(c_request);
}
char *UlfiusRequest_getPath(CUlfiusRequest *c_request)
{
    UlfiusRequest *request = reinterpret_cast<UlfiusRequest*>(c_request);
    std::string path = request->getPath();

    return const_cast<char *>(path.c_str());
}
char *UlfiusRequest_getMethod(CUlfiusRequest *c_request)
{
    UlfiusRequest *request = reinterpret_cast<UlfiusRequest*>(c_request);
    std::string method = request->getMethod();

    return const_cast<char *>(method.c_str());
}
char *UlfiusRequest_getHeader(CUlfiusRequest *c_request, const char *c_header)
{
    UlfiusRequest *request = reinterpret_cast<UlfiusRequest*>(c_request);
    const std::string header(c_header);
    std::string header_value = request->getHeader(header);

    return const_cast<char *>(header_value.c_str());
}
uint8_t *UlfiusRequest_getBody(CUlfiusRequest *c_request)
{
    // XXX: note that body should be freed after use!
    UlfiusRequest *request = reinterpret_cast<UlfiusRequest*>(c_request);
    std::vector<uint8_t> body = request->getBody();
    uint8_t *c_body = static_cast<uint8_t *>(malloc(sizeof(uint8_t) * body.size()));

    std::copy(body.begin(), body.end(), c_body);

    return c_body;
}

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

    for (header_iterator=0; ulfius_map->keys[header_iterator] != NULL; header_iterator++) {
        key = ulfius_map->keys[header_iterator];
        if (ulfius_map->lengths[header_iterator] > 0) {
            value = ulfius_map->values[header_iterator];
        } else {
            value = "";
        }
        std_map.insert(std::make_pair(key, value));
    }

    return std_map;
}

UlfiusRequest::UlfiusRequest(const struct _u_request *u_request)
{
    uint8_t *uint_body = (uint8_t*)u_request->binary_body;
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
