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

#include <string.h>

#include "logging.h"
#include "restserver.h"

bool valid_callback_url(const char *url)
{
    // TODO: implement
    return true;
}

bool validate_callback(json_t *jcallback, rest_context_t *rest)
{
    json_t *url, *jheaders;
    const char *header;
    json_t *value;
    int res;
    const char *callback_url;
    ulfius_req_t test_request;
    ulfius_resp_t test_response;
    struct _u_map headers;
    bool validation_state = true;
    json_t *jbody = json_pack("{s:[], s:[], s:[], s:[]}",
                              "registrations", "reg-updates",
                              "async-responses", "de-registrations");


    if (jcallback == NULL)
    {
        return false;
    }

    // Must be an object with "url" and "headers"
    if (!json_is_object(jcallback) || json_object_size(jcallback) != 2)
    {
        return false;
    }

    // "url" must be a string with valid url
    url = json_object_get(jcallback, "url");
    if (!json_is_string(url) || !valid_callback_url(json_string_value(url)))
    {
        return false;
    }

    // "header" must be an object...
    jheaders = json_object_get(jcallback, "headers");
    if (!json_is_object(jheaders))
    {
        return false;
    }

    u_map_init(&headers);
    // ... which contains string key-value pairs
    json_object_foreach(jheaders, header, value)
    {
        if (!json_is_string(value))
        {
            u_map_clean(&headers);

            return false;
        }

        u_map_put(&headers, header, json_string_value(value));
    }

    callback_url = json_string_value(url);

    ulfius_init_request(&test_request);
    test_request.http_verb = strdup("PUT");
    test_request.http_url = strdup(callback_url);
    test_request.timeout = 20;
    test_request.check_server_certificate = 0;
    test_request.client_cert_file = o_strdup(rest->settings->http.security.certificate);
    test_request.client_key_file = o_strdup(rest->settings->http.security.private_key);
    if ((rest->settings->http.security.certificate != NULL && test_request.client_cert_file == NULL) ||
        (rest->settings->http.security.private_key != NULL && test_request.client_key_file == NULL))
    {
        log_message(LOG_LEVEL_ERROR, "[CALLBACK] Failed to set client security credentials\n");

        json_decref(jbody);
        u_map_clean(&headers);
        ulfius_clean_request(&test_request);

        return -1;
    }

    u_map_copy_into(test_request.map_header, &headers);
    ulfius_set_json_body_request(&test_request, jbody);
    json_decref(jbody);

    ulfius_init_response(&test_response);
    res = ulfius_send_http_request(&test_request, &test_response);

    if (res != U_OK)
    {
        log_message(LOG_LEVEL_WARN, "Callback \"%s\" is not reachable.\n", callback_url);

        validation_state = false;
    }

    u_map_clean(&headers);
    ulfius_clean_response(&test_response);
    ulfius_clean_request(&test_request);

    return validation_state;
}

int rest_notifications_get_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                       void *context)
{
    rest_context_t *rest = (rest_context_t *)context;

    rest_lock(rest);

    if (rest->callback == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
    }
    else
    {
        ulfius_set_json_body_response(resp, 200, rest->callback);
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_put_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                       void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    const char *ct;
    const char *callback_url;
    json_t *jcallback;

    ct = u_map_get_case(req->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(resp, 415);
        return U_CALLBACK_COMPLETE;
    }

    jcallback = json_loadb(req->binary_body, req->binary_body_length, 0, NULL);
    if (!validate_callback(jcallback, rest))
    {
        if (jcallback != NULL)
        {
            json_decref(jcallback);
        }

        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    callback_url = json_string_value(json_object_get(jcallback, "url"));
    log_message(LOG_LEVEL_INFO, "[SET-CALLBACK] url=%s\n", callback_url);

    rest_lock(rest);

    if (rest->callback != NULL)
    {
        json_decref(rest->callback);
        rest->callback = NULL;
    }

    rest->callback = jcallback;

    ulfius_set_empty_body_response(resp, 204);

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_delete_callback_cb(const ulfius_req_t *req, ulfius_resp_t *resp,
                                          void *context)
{
    rest_context_t *rest = (rest_context_t *)context;

    rest_lock(rest);

    if (rest->callback != NULL)
    {
        log_message(LOG_LEVEL_INFO, "[DELETE-CALLBACK] url=%s\n",
                    json_string_value(json_object_get(rest->callback, "url")));

        json_decref(rest->callback);
        rest->callback = NULL;

        ulfius_set_empty_body_response(resp, 204);
    }
    else
    {
        log_message(LOG_LEVEL_WARN, "[DELETE-CALLBACK] No callbacks to delete\n");

        ulfius_set_empty_body_response(resp, 404);
    }

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_pull_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;

    rest_lock(rest);

    json_t *jbody = rest_notifications_json(rest);

    rest_notifications_clear(rest);

    ulfius_set_json_body_response(resp, 200, jbody);
    json_decref(jbody);

    rest_unlock(rest);

    return U_CALLBACK_COMPLETE;
}

void rest_notify_registration(rest_context_t *rest, rest_notif_registration_t *reg)
{
    rest_list_add(rest->registrationList, reg);
}

void rest_notify_update(rest_context_t *rest, rest_notif_update_t *update)
{
    rest_list_add(rest->updateList, update);
}

void rest_notify_deregistration(rest_context_t *rest, rest_notif_deregistration_t *dereg)
{
    rest_list_add(rest->deregistrationList, dereg);
}

void rest_notify_timeout(rest_context_t *rest, rest_notif_timeout_t *timeout)
{
    rest_list_add(rest->timeoutList, timeout);
}

void rest_notify_async_response(rest_context_t *rest, rest_notif_async_response_t *resp)
{
    rest_list_add(rest->asyncResponseList, resp);
}

static json_t *rest_async_response_to_json(rest_async_response_t *async)
{
    json_t *jasync = json_object();

    json_object_set_new(jasync, "timestamp", json_integer(async->timestamp));
    json_object_set_new(jasync, "id", json_string(async->id));
    json_object_set_new(jasync, "status", json_integer(async->status));
    json_object_set_new(jasync, "payload", json_string(async->payload));

    return jasync;
}

static json_t *rest_registration_notification_to_json(rest_notif_registration_t *registration)
{
    json_t *jreg = json_object();

    json_object_set_new(jreg, "name", json_string(registration->name));

    return jreg;
}

static json_t *rest_update_notification_to_json(rest_notif_update_t *update)
{
    json_t *jupdate = json_object();

    json_object_set_new(jupdate, "name", json_string(update->name));

    return jupdate;
}

static json_t *rest_deregistration_notification_to_json(rest_notif_deregistration_t *deregistration)
{
    json_t *jdereg = json_object();

    json_object_set_new(jdereg, "name", json_string(deregistration->name));

    return jdereg;
}

json_t *rest_notifications_json(rest_context_t *rest)
{
    json_t *jnotifs;
    json_t *jarray;
    rest_list_entry_t *entry;
    rest_notif_registration_t *reg;
    rest_notif_update_t *upd;
    rest_notif_deregistration_t *dereg;
    rest_notif_async_response_t *async;

    jnotifs = json_object();

    if (rest->registrationList)
    {
        jarray = json_array();
        for (entry = rest->registrationList->head; entry != NULL; entry = entry->next)
        {
            reg = entry->data;
            json_array_append_new(jarray, rest_registration_notification_to_json(reg));
        }
        json_object_set_new(jnotifs, "registrations", jarray);
    }

    if (rest->updateList)
    {
        jarray = json_array();
        for (entry = rest->updateList->head; entry != NULL; entry = entry->next)
        {
            upd = entry->data;
            json_array_append_new(jarray, rest_update_notification_to_json(upd));
        }
        json_object_set_new(jnotifs, "reg-updates", jarray);
    }

    if (rest->deregistrationList)
    {
        jarray = json_array();
        for (entry = rest->deregistrationList->head; entry != NULL; entry = entry->next)
        {
            dereg = entry->data;
            json_array_append_new(jarray, rest_deregistration_notification_to_json(dereg));
        }
        json_object_set_new(jnotifs, "de-registrations", jarray);
    }

    if (rest->asyncResponseList)
    {
        jarray = json_array();
        for (entry = rest->asyncResponseList->head; entry != NULL; entry = entry->next)
        {
            async = entry->data;
            json_array_append_new(jarray, rest_async_response_to_json(async));
        }
        json_object_set_new(jnotifs, "async-responses", jarray);
    }

    return jnotifs;
}

void rest_notifications_clear(rest_context_t *rest)
{
    while (rest->registrationList->head != NULL)
    {
        rest_notif_registration_t *reg = rest->registrationList->head->data;
        rest_list_remove(rest->registrationList, reg);
        rest_notif_registration_delete(reg);
    }

    while (rest->updateList->head != NULL)
    {
        rest_notif_update_t *upd = rest->updateList->head->data;
        rest_list_remove(rest->updateList, upd);
        rest_notif_update_delete(upd);
    }

    while (rest->deregistrationList->head != NULL)
    {
        rest_notif_deregistration_t *dereg = rest->deregistrationList->head->data;
        rest_list_remove(rest->deregistrationList, dereg);
        rest_notif_deregistration_delete(dereg);
    }

    while (rest->asyncResponseList->head != NULL)
    {
        rest_notif_async_response_t *async = rest->asyncResponseList->head->data;
        rest_list_remove(rest->asyncResponseList, async);
        rest_async_response_delete(async);
    }
}

