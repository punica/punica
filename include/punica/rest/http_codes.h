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

#ifndef PUNICA_REST_HTTP_CODES_H
#define PUNICA_REST_HTTP_CODES_H

/* 1xx: Informational
   Request received, continuing process */
#define HTTP_100_CONTINUE                              100
#define HTTP_101_SWITCHING_PROTOCOLS                   101

/* 2xx: Success
   The action was successfully received, understood, and accepted */
#define HTTP_200_OK                                    200
#define HTTP_201_CREATED                               201
#define HTTP_202_ACCEPTED                              202
#define HTTP_203_NON_AUTHORITATIVE_INFORMATION         203
#define HTTP_204_NO_CONTENT                            204
#define HTTP_205_RESET_CONTENT                         205
#define HTTP_206_PARTIAL_CONTENT                       205

/* 4xx: Client Error
   The request contains bad syntax or cannot be fulfilled */
#define HTTP_400_BAD_REQUEST                           400
#define HTTP_401_UNAUTHORIZED                          401
#define HTTP_403_FORBIDDEN                             403
#define HTTP_404_NOT_FOUND                             404
#define HTTP_405_METHOD_NOT_ALLOWED                    405
#define HTTP_406_NOT_ACCEPTABLE                        406
#define HTTP_408_REQUEST_TIMEOUT                       408
#define HTTP_409_CONFLICT                              409
#define HTTP_410_GONE                                  410
#define HTTP_413_PAYLOAD_TOO_LARGE                     413
#define HTTP_414_URI_TOO_LONG                          414
#define HTTP_415_UNSUPPORTED_MEDIA_TYPE                415

/* 5xx: Server Error
   The server failed to fulfill an apparently valid request */
#define HTTP_500_INTERNAL_ERROR                        500
#define HTTP_501_NOT_IMPLEMENTED                       501

#endif // PUNICA_REST_HTTP_CODES_H
