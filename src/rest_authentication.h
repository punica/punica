/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2018 8devices
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

#ifndef REST_AUTHENTICATION_H
#define REST_AUTHENTICATION_H

#include <ulfius.h>

#define HEADER_AUTHORIZATION   "Authorization"
#define HEADER_UNAUTHORIZED    "WWW-Authenticate"
#define HEADER_PREFIX_BEARER   "Bearer "

int rest_authenticate_cb(const struct _u_request *request, struct _u_response *response,
                         void *user_data);
int rest_validate_jwt_cb(const struct _u_request *request, struct _u_response *response,
                         void *user_data);

#endif // REST_AUTHENTICATION_H
