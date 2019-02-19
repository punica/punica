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

#ifndef REST_CALLBACKS_H
#define REST_CALLBACKS_H

#include <ulfius.h>

typedef int (ulfius_callback_t)(const struct _u_request *u_request,
                                struct _u_response *u_response,
                                void *context);

ulfius_callback_t rest_authenticate_cb;
ulfius_callback_t rest_validate_jwt_cb;

ulfius_callback_t rest_endpoints_cb;
ulfius_callback_t rest_endpoints_name_cb;

ulfius_callback_t rest_devices_get_cb;
ulfius_callback_t rest_devices_get_name_cb;
ulfius_callback_t rest_devices_put_cb;
ulfius_callback_t rest_devices_post_cb;
ulfius_callback_t rest_devices_delete_cb;

ulfius_callback_t rest_resources_rwe_cb;

ulfius_callback_t rest_notifications_get_callback_cb;
ulfius_callback_t rest_notifications_put_callback_cb;
ulfius_callback_t rest_notifications_delete_callback_cb;
ulfius_callback_t rest_notifications_pull_cb;

ulfius_callback_t rest_subscriptions_put_cb;
ulfius_callback_t rest_subscriptions_delete_cb;

ulfius_callback_t rest_version_cb;

#endif // REST_CALLBACKS_H
