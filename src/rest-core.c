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

#include <assert.h>
#include <string.h>

#include "logging.h"
#include "punica.h"
#include "database.h"

void rest_init(rest_context_t *rest, settings_t *settings)
{
    memset(rest, 0, sizeof(rest_context_t));

    rest->registrationList = rest_list_new();
    rest->updateList = rest_list_new();
    rest->deregistrationList = rest_list_new();
    rest->timeoutList = rest_list_new();
    rest->asyncResponseList = rest_list_new();
    rest->pendingResponseList = rest_list_new();
    rest->observeList = rest_list_new();
    rest->settings = settings;

    assert(pthread_mutex_init(&rest->mutex, NULL) == 0);

    database_load_file(rest);
}

void rest_cleanup(rest_context_t *rest)
{
    if (rest->callback)
    {
        json_decref(rest->callback);
        rest->callback = NULL;
    }

    rest_notifications_clear(rest);
    rest_list_delete(rest->registrationList);
    rest_list_delete(rest->updateList);
    rest_list_delete(rest->deregistrationList);
    rest_list_delete(rest->timeoutList);
    rest_list_delete(rest->asyncResponseList);
    rest_list_delete(rest->pendingResponseList);
    rest_list_delete(rest->observeList);

    assert(pthread_mutex_destroy(&rest->mutex) == 0);
}

int rest_step(rest_context_t *rest, struct timeval *tv)
{
    ulfius_req_t request;
    ulfius_resp_t response;
    json_t *jbody;
    json_t *jheaders;
    json_t *value;
    const char *header;
    struct _u_map headers;
    int res;

    if ((rest->registrationList->head != NULL
         || rest->updateList->head != NULL
         || rest->deregistrationList->head != NULL
         || rest->asyncResponseList->head != NULL)
        && rest->callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->callback, "url"));
        jheaders = json_object_get(rest->callback, "headers");
        u_map_init(&headers);
        json_object_foreach(jheaders, header, value)
        {
            u_map_put(&headers, header, json_string_value(value));
        }

        log_message(LOG_LEVEL_INFO, "[CALLBACK] Sending to %s\n", url);

        jbody = rest_notifications_json(rest);

        ulfius_init_request(&request);
        request.http_verb = strdup("PUT");
        request.http_url = strdup(url);
        request.timeout = 20;
        request.check_server_certificate = 0;
        request.client_cert_file = o_strdup(rest->settings->http.security.certificate);
        request.client_key_file = o_strdup(rest->settings->http.security.private_key);
        if ((rest->settings->http.security.certificate != NULL && request.client_cert_file == NULL) ||
            (rest->settings->http.security.private_key != NULL && request.client_key_file == NULL))
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
            rest_notifications_clear(rest);
        }

        u_map_clean(&headers);
        ulfius_clean_request(&request);
        ulfius_clean_response(&response);
    }

    return 0;
}

void rest_lock(rest_context_t *rest)
{
    assert(pthread_mutex_lock(&rest->mutex) == 0);
}

void rest_unlock(rest_context_t *rest)
{
    assert(pthread_mutex_unlock(&rest->mutex) == 0);
}

