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

#define HEADER_AUTHORIZATION "Authorization"
#define HEADER_UNAUTHORIZED "WWW-Authenticate"
#define HEADER_PREFIX_BEARER "Bearer "

#define ERROR_DESCRIPTION_INVALID_TOKEN \
"error=\"invalid_request\",error_description=\"The access token is missing\""
#define ERROR_DESCRIPTION_INVALID_SCOPE \
"error=\"invalid_token\",error_description=\"The access token is invalid\""
#define ERROR_DESCRIPTION_INSUFFICIENT_SCOPE \
"error=\"invalid_scope\",error_description=\"The scope is invalid\""

#endif // REST_AUTHENTICATION_H
