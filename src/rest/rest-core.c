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

#include "rest_core.h"

#include <assert.h>
#include <string.h>

#include "../linked_list.h"
#include "../logging.h"

void rest_initialize(rest_core_t *rest)
{
    memset(rest, 0, sizeof(rest_core_t));

    rest->registrationList = linked_list_new();
    rest->updateList = linked_list_new();
    rest->deregistrationList = linked_list_new();
    rest->timeoutList = linked_list_new();
    rest->asyncResponseList = linked_list_new();
    rest->pendingResponseList = linked_list_new();
    rest->observeList = linked_list_new();
}

void rest_terminate(rest_core_t *rest)
{
    if (rest->callback)
    {
        json_decref(rest->callback);
        rest->callback = NULL;
    }

    rest_notifications_clear(rest);
    linked_list_delete(rest->registrationList);
    linked_list_delete(rest->updateList);
    linked_list_delete(rest->deregistrationList);
    linked_list_delete(rest->timeoutList);
    linked_list_delete(rest->asyncResponseList);
    linked_list_delete(rest->pendingResponseList);
    linked_list_delete(rest->observeList);
    linked_list_delete(rest->observeList);
}

int rest_step(rest_core_t *rest, struct timeval *tv, http_settings_t *settings)
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
        request.client_cert_file = o_strdup(settings->security.certificate);
        request.client_key_file = o_strdup(settings->security.private_key);
        if ((settings->security.certificate != NULL && request.client_cert_file == NULL) ||
            (settings->security.private_key != NULL && request.client_key_file == NULL))
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

