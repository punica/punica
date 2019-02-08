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
#include "rest.h"

#include <assert.h>
#include <string.h>

int rest_step(punica_context_t *rest, struct timeval *tv)
{
    struct _u_request u_request;
    struct _u_response u_response;
    struct _u_map headers;
    json_t *jbody;
    json_t *jheaders;
    json_t *value;
    const char *header;
    int res;

    if ((rest->rest_registrations->head != NULL
         || rest->rest_updates->head != NULL
         || rest->rest_deregistrations->head != NULL
         || rest->rest_async_responses->head != NULL)
        && rest->j_callback != NULL)
    {
        const char *url = json_string_value(json_object_get(rest->j_callback, "url"));
        jheaders = json_object_get(rest->j_callback, "headers");
        u_map_init(&headers);
        json_object_foreach(jheaders, header, value)
        {
            u_map_put(&headers, header, json_string_value(value));
        }

        log_message(LOG_LEVEL_INFO, "[CALLBACK] Sending to %s\n", url);

        jbody = rest_notifications_json(rest);

        ulfius_init_request(&u_request);
        u_request.http_verb = strdup("PUT");
        u_request.http_url = strdup(url);
        u_request.timeout = 20;
        u_request.check_server_certificate = 0;
        u_request.client_cert_file = o_strdup(rest->settings->http.security.certificate);
        u_request.client_key_file = o_strdup(rest->settings->http.security.private_key);
        if ((rest->settings->http.security.certificate != NULL && u_request.client_cert_file == NULL) ||
            (rest->settings->http.security.private_key != NULL && u_request.client_key_file == NULL))
        {
            log_message(LOG_LEVEL_ERROR, "[CALLBACK] Failed to set client security credentials\n");

            json_decref(jbody);
            u_map_clean(&headers);
            ulfius_clean_request(&u_request);

            return -1;
        }

        u_map_copy_into(u_request.map_header, &headers);

        ulfius_set_json_body_request(&u_request, jbody);
        json_decref(jbody);

        ulfius_init_response(&u_response);
        res = ulfius_send_http_request(&u_request, &u_response);
        if (res == U_OK)
        {
            rest_notifications_clear(rest);
        }

        u_map_clean(&headers);
        ulfius_clean_request(&u_request);
        ulfius_clean_response(&u_response);
    }

    return 0;
}
