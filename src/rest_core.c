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

#include "logging.h"
#include "punica.h"

#include <assert.h>
#include <string.h>

void punica_init(punica_context_t *punica, settings_t *settings)
{
    memset(punica, 0, sizeof(punica_context_t));

    punica->registrationList = linked_list_new();
    punica->updateList = linked_list_new();
    punica->deregistrationList = linked_list_new();
    punica->timeoutList = linked_list_new();
    punica->asyncResponseList = linked_list_new();
    punica->pendingResponseList = linked_list_new();
    punica->observeList = linked_list_new();
    punica->settings = settings;

    assert(pthread_mutex_init(&punica->mutex, NULL) == 0);
}

void punica_cleanup(punica_context_t *punica)
{
    if (punica->callback)
    {
        json_decref(punica->callback);
        punica->callback = NULL;
    }

    rest_notifications_clear(punica);
    linked_list_delete(punica->registrationList);
    linked_list_delete(punica->updateList);
    linked_list_delete(punica->deregistrationList);
    linked_list_delete(punica->timeoutList);
    linked_list_delete(punica->asyncResponseList);
    linked_list_delete(punica->pendingResponseList);
    linked_list_delete(punica->observeList);

    assert(pthread_mutex_destroy(&punica->mutex) == 0);
}

int punica_step(punica_context_t *punica, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    json_t *jbody;
    json_t *jheaders;
    json_t *value;
    const char *header;
    struct _u_map headers;
    int res;

    if ((punica->registrationList->head != NULL
         || punica->updateList->head != NULL
         || punica->deregistrationList->head != NULL
         || punica->asyncResponseList->head != NULL)
        && punica->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(punica->callback, "url"));
        jheaders = json_object_get(punica->callback, "headers");
        u_map_init(&headers);
        json_object_foreach(jheaders, header, value)
        {
            u_map_put(&headers, header, json_string_value(value));
        }

        log_message(LOG_LEVEL_INFO, "[CALLBACK] Sending to %s\n", url);

        jbody = rest_notifications_json(punica);

        ulfius_init_request(&request);
        request.http_verb = strdup("PUT");
        request.http_url = strdup(url);
        request.timeout = 20;
        request.check_server_certificate = 0;
        request.client_cert_file = o_strdup(punica->settings->http.security.certificate);
        request.client_key_file = o_strdup(punica->settings->http.security.private_key);
        if ((punica->settings->http.security.certificate != NULL && request.client_cert_file == NULL) ||
            (punica->settings->http.security.private_key != NULL && request.client_key_file == NULL))
        {
            log_message(LOG_LEVEL_ERROR, "[CALLBACK] Failed to set client security credentials\n");

            json_decref(jbody);
            u_map_clean(&headers);
            ulfius_clean_request(&request);

            return -1;
        }

        u_map_copy_into(request.map_header, &headers);

        ulfius_set_json_body_request(&request, jbody);
        json_decref(jbody);

        ulfius_init_response(&response);
        res = ulfius_send_http_request(&request, &response);
        if (res == U_OK)
        {
            rest_notifications_clear(punica);
        }

        u_map_clean(&headers);
        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

void punica_lock(punica_context_t *punica)
{
    assert(pthread_mutex_lock(&punica->mutex) == 0);
}

void punica_unlock(punica_context_t *punica)
{
    assert(pthread_mutex_unlock(&punica->mutex) == 0);
}

