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

/*
 * Connection API functions. Used for socket creation, management and communication.
 * API initialization depends on communication instance implementation:
 *
 *      For UDP sockets call udp_connection_api_init()
 *
 *      For DTLS sockets call dtls_connection_api_init()
 *
 * Refer to said functions prototypes for further instructions.
 * All API initialization functions set an connection_api_t pointer that needs to be
 * provided to all API functions as the first parameter.
*/

/*
 * Initializes and starts a connection context
 *
 * Prototype:
 *      f_start(void *context);
 *
 * Parameters:
 *      context - connection context pointer
 *
 * Returns:
 *      0 on success,
 *      negative value on error
*/
typedef int (*f_start_t)(void *);
/*
 * POSIX recv style function that deals with incoming connections
 * and fills provided buffer with received data
 *
 * Prototype:
 *      f_receive(void *context, uint8_t *buffer, size_t size, void **connection,
 *                struct timeval *tv);
 *
 * Parameters:
 *      context - connection context pointer,
 *      buffer - preallocated buffer for received data storing,
 *      size - length of buffer,
 *      connection - server/client connection context for upper communications layers.
 *      Has set value after return,
 *      tv - timeout value
 *
 * Returns:
 *      0 on no data available,
 *      positive value of length of data received,
 *      negative value on error
*/
typedef int (*f_receive_t)(void *, uint8_t *, size_t, void **, struct timeval *);
/*
 * Send data to peer
 *
 * Prototype:
 *      f_send(void *context, void *connection, uint8_t *buffer, size_t length);
 *
 * Parameters:
 *      context - connection context pointer,
 *      connection - server/client connection context for upper communications layers,
 *      buffer - data to be sent,
 *      length - length of data to be sent
 *
 * Returns:
 *      0 on success,
 *      negative value on error
*/
typedef int (*f_send_t)(void *, void *, uint8_t *, size_t);
/*
 * Close connection with peer
 *
 * Prototype:
 *      f_close(void *context, void *connection);
 *
 * Parameters:
 *      context - connection context pointer,
 *      connection - server/client connection context for upper communications layers
 *
 * Returns:
 *      0 on success,
 *      negative value on error
*/
typedef int (*f_close_t)(void *, void *);
/*
 * Stops and deinitializes communication context. Closes connections with all peers
 *
 * Prototype:
 *      f_stop(void *context);
 *
 * Parameters:
 *      context - connection context pointer
 *
 * Returns:
 *      0 on success,
 *      negative value on error
*/
typedef int (*f_stop_t)(void *);

typedef struct connection_api_t
{
    f_start_t   f_start;
    f_receive_t f_receive;
    f_send_t    f_send;
    f_close_t   f_close;
    f_stop_t    f_stop;
} connection_api_t;

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
} rest_context_t;

lwm2m_client_t *rest_endpoints_find_client(lwm2m_client_t *list, const char *name);

int rest_endpoints_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_endpoints_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);


void rest_notify_registration(rest_context_t *rest, rest_notif_registration_t *reg);
void rest_notify_update(rest_context_t *rest, rest_notif_update_t *update);
void rest_notify_deregistration(rest_context_t *rest, rest_notif_deregistration_t *dereg);
void rest_notify_timeout(rest_context_t *rest, rest_notif_timeout_t *timeout);
void rest_notify_async_response(rest_context_t *rest, rest_notif_async_response_t *resp);

json_t *rest_notifications_json(rest_context_t *rest);

void rest_notifications_clear(rest_context_t *rest);

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_notifications_delete_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                          void *context);


int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

int rest_version_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

void rest_init(rest_context_t *rest, settings_t *settings);
void rest_cleanup(rest_context_t *rest);
int rest_step(rest_context_t *rest, struct timeval *tv);

void rest_lock(rest_context_t *rest);
void rest_unlock(rest_context_t *rest);

int rest_devices_get_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_get_name_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_post_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);
int rest_devices_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context);

#endif // RESTSERVER_H

