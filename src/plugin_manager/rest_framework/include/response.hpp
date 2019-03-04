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

#ifndef RESPONSE_HPP
#define RESPONSE_HPP

#include <map>
#include <string>
#include <vector>

#include <stdint.h>

enum StatusCode {
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
    virtual void setHeader(const std::string header, const std::string value) = 0;
};

#endif // RESPONSE_HPP
