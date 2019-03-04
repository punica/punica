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

#ifndef ULFIUS_RESPONSE_H
#define ULFIUS_RESPONSE_H

#include "response.h"

struct CUlfiusResponse;
typedef struct CUlfiusResponse CUlfiusResponse;
CUlfiusResponse *new_UlfiusResponse(struct _u_response *u_response);
void delete_UlfiusResponse(CUlfiusResponse *c_response);
void UlfiusResponse_setBody(CUlfiusResponse *c_response, uint8_t *c_binary_data, size_t size);
void UlfiusResponse_setCode(CUlfiusResponse *c_response, const CStatusCode c_code);
void UlfiusResponse_setHeader(CUlfiusResponse *c_response,
                                      const char *c_header, const char *c_value);

#endif // ULFIUS_RESPONSE_H
