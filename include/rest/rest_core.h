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

#ifndef REST_CORE_H
#define REST_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "request.h"
#include "response.h"

typedef CStatusCode(*c_callback_function_t)(CRequest *, CResponse *, void *);

struct CRestCore;
typedef struct CRestCore CRestCore;

void RestCore_addHandler(CRestCore *c_rest_core,
                              const char *method,
                              const char *url_prefix,
                              const unsigned int priority,
                              c_callback_function_t c_handler_function,
                              void *handler_context);

#ifdef __cplusplus
}
#endif

#endif // REST_CORE_H
