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

#ifndef REST_CORE_H
#define REST_CORE_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "../settings.h"
#include "http_codes.h"
#include "rest-core-types.h"
#include "rest-utils.h"

typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    // rest-core
    json_t *callback;

    // rest-notifications
    linked_list_t *registrationList;
    linked_list_t *updateList;
    linked_list_t *deregistrationList;
    linked_list_t *timeoutList;
    linked_list_t *asyncResponseList;

    // rest-resources
    linked_list_t *pendingResponseList;

    // rest-subsciptions
    linked_list_t *observeList;

    // rest-devices
    linked_list_t *devicesList;
} rest_core_t;

void rest_initialize(rest_core_t *rest);
void rest_terminate(rest_core_t *rest);

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);


void rest_notify_registration(rest_core_t *rest, rest_notif_registration_t *reg);
void rest_notify_update(rest_core_t *rest, rest_notif_update_t *update);
void rest_notify_deregistration(rest_core_t *rest, rest_notif_deregistration_t *dereg);
void rest_notify_timeout(rest_core_t *rest, rest_notif_timeout_t *timeout);
void rest_notify_async_response(rest_core_t *rest, rest_notif_async_response_t *resp);

json_t *rest_notifications_json(rest_core_t *rest);

void rest_notifications_clear(rest_core_t *rest);

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_delete_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                          void *context);


int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_step(rest_core_t *rest, struct timeval *tv, http_settings_t *settings);

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

#endif // PUNICA_CORE_H

