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

#ifndef PUNICA_H
#define PUNICA_H

#include "http_codes.h"
#include "rest_core_types.h"
#include "utils.h"
#include "settings.h"

#include <liblwm2m.h>
#include <ulfius.h>

typedef struct _u_request ulfius_req_t;
typedef struct _u_response ulfius_resp_t;

typedef struct
{
    pthread_mutex_t mutex;

    lwm2m_context_t *lwm2m;

    // punica-core
    json_t *callback;

    // punica-notifications
    linked_list_t *registrationList;
    linked_list_t *updateList;
    linked_list_t *deregistrationList;
    linked_list_t *timeoutList;
    linked_list_t *asyncResponseList;

    // punica-resources
    linked_list_t *pendingResponseList;

    // punica-subsciptions
    linked_list_t *observeList;

    settings_t *settings;
} punica_context_t;

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

void rest_notify_registration(punica_context_t *punica, rest_notif_registration_t *reg);
void rest_notify_update(punica_context_t *punica, rest_notif_update_t *update);
void rest_notify_deregistration(punica_context_t *punica, rest_notif_deregistration_t *dereg);
void rest_notify_timeout(punica_context_t *punica, rest_notif_timeout_t *timeout);
void rest_notify_async_response(punica_context_t *punica, rest_notif_async_response_t *resp);

json_t *rest_notifications_json(punica_context_t *punica);

void rest_notifications_clear(punica_context_t *punica);

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_delete_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                          void *context);

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int punica_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

void punica_init(punica_context_t *punica, settings_t *settings);
void punica_cleanup(punica_context_t *punica);
int rest_step(punica_context_t *punica, struct timeval *tv);

void punica_lock(punica_context_t *punica);
void punica_unlock(punica_context_t *punica);

#endif // PUNICA_H

