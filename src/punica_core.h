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

#ifndef RESTSERVER_H
#define RESTSERVER_H

#include <liblwm2m.h>
#include <ulfius.h>

#include "http_codes.h"
#include "rest-core-types.h"
#include "rest-utils.h"
#include "settings.h"


typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    pthread_mutex_t mutex;

    lwm2m_context_t *lwm2m;

    // rest-core
    json_t *callback;

    // rest-notifications
    rest_list_t *registrationList;
    rest_list_t *updateList;
    rest_list_t *deregistrationList;
    rest_list_t *timeoutList;
    rest_list_t *asyncResponseList;

    // rest-resources
    rest_list_t *pendingResponseList;

    // rest-subsciptions
    rest_list_t *observeList;

    // rest-devices
    rest_list_t *devicesList;

    settings_t *settings;
} punica_core_t;

lwm2m_client_t *rest_endpoints_find_client(lwm2m_client_t *list, const char *name);

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);


void rest_notify_registration(punica_core_t *punica, rest_notif_registration_t *reg);
void rest_notify_update(punica_core_t *punica, rest_notif_update_t *update);
void rest_notify_deregistration(punica_core_t *punica, rest_notif_deregistration_t *dereg);
void rest_notify_timeout(punica_core_t *punica, rest_notif_timeout_t *timeout);
void rest_notify_async_response(punica_core_t *punica, rest_notif_async_response_t *resp);

json_t *rest_notifications_json(punica_core_t *punica);

void rest_notifications_clear(punica_core_t *punica);

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_delete_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                          void *context);


int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

void rest_init(punica_core_t *punica, settings_t *settings);
void rest_cleanup(punica_core_t *punica);
int rest_step(punica_core_t *punica, struct timeval *tv);

void rest_lock(punica_core_t *punica);
void rest_unlock(punica_core_t *punica);

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

#endif // RESTSERVER_H

