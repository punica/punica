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

#ifndef ULFIUS_REQUEST_H
#define ULFIUS_REQUEST_H

#include "request.h"

struct CUlfiusRequest;
typedef struct CUlfiusRequest CUlfiusRequest;
CUlfiusRequest *new_UlfiusRequest(const struct _u_request *u_request);
void delete_UlfiusRequest(CUlfiusRequest *c_request);
char *UlfiusRequest_getPath(CUlfiusRequest *c_request);
char *UlfiusRequest_getMethod(CUlfiusRequest *c_request);
char *UlfiusRequest_getHeader(CUlfiusRequest *c_request, const char *c_header);
uint8_t *UlfiusRequest_getBody(CUlfiusRequest *c_request);

#endif // ULFIUS_REQUEST_H
