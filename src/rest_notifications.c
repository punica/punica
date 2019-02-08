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

#include "http_codes.h"
#include "logging.h"
#include "rest.h"

#include <string.h>

bool valid_callback_url(const char *url)
{
    // TODO: implement
    return true;
}

bool validate_callback(json_t *j_callback, punica_context_t *punica)
{
    json_t *j_url, *j_headers;
    const char *header;
    json_t *j_value;
    int res;
    const char *callback_url;
    struct _u_request test_request;
    struct _u_response test_response;
    struct _u_map headers;
    bool validation_state = true;
    json_t *j_body = json_pack("{s:[], s:[], s:[], s:[]}",
                               "registrations", "reg-updates",
                               "async-responses", "de-registrations");

    if (j_callback == NULL)
    {
        return false;
    }

    // Must be an object with "url" and "headers"
    if (!json_is_object(j_callback) || json_object_size(j_callback) != 2)
    {
        return false;
    }

    // "url" must be a string with valid url
    j_url = json_object_get(j_callback, "url");
    if (!json_is_string(j_url) || !valid_callback_url(json_string_value(j_url)))
    {
        return false;
    }

    // "header" must be an object...
    j_headers = json_object_get(j_callback, "headers");
    if (!json_is_object(j_headers))
    {
        return false;
    }

    u_map_init(&headers);
    // ... which contains string key-value pairs
    json_object_foreach(j_headers, header, j_value)
    {
        if (!json_is_string(j_value))
        {
            u_map_clean(&headers);

            return false;
        }

        u_map_put(&headers, header, json_string_value(j_value));
    }

    callback_url = json_string_value(j_url);

    ulfius_init_request(&test_request);
    test_request.http_verb = strdup("PUT");
    test_request.http_url = strdup(callback_url);
    test_request.timeout = 20;
    test_request.check_server_certificate = 0;
    test_request.client_cert_file = o_strdup(punica->settings->http.security.certificate);
    test_request.client_key_file = o_strdup(punica->settings->http.security.private_key);
    if ((punica->settings->http.security.certificate != NULL &&
         test_request.client_cert_file == NULL) ||
        (punica->settings->http.security.private_key != NULL && test_request.client_key_file == NULL))
    {
        log_message(LOG_LEVEL_ERROR, "[CALLBACK] Failed to set client security credentials\n");

        json_decref(j_body);
        u_map_clean(&headers);
        ulfius_clean_request(&test_request);

        return -1;
    }

    u_map_copy_into(test_request.map_header, &headers);
    ulfius_set_json_body_request(&test_request, j_body);
    json_decref(j_body);

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

int rest_notifications_get_callback_cb(const struct _u_request *u_request,
                                       struct _u_response *u_response,
                                       void *context)
{
    punica_context_t *punica = (punica_context_t *)context;

    punica_lock(punica);

    if (punica->j_callback == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
    }
    else
    {
        ulfius_set_json_body_response(u_response, HTTP_200_OK, punica->j_callback);
    }

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_put_callback_cb(const struct _u_request *u_request,
                                       struct _u_response *u_response,
                                       void *context)
{
    punica_context_t *punica = (punica_context_t *)context;
    const char *ct;
    const char *callback_url;
    json_t *j_callback;

    ct = u_map_get_case(u_request->map_header, "Content-Type");
    if (ct == NULL || strcmp(ct, "application/json") != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_415_UNSUPPORTED_MEDIA_TYPE);
        return U_CALLBACK_COMPLETE;
    }

    j_callback = json_loadb(u_request->binary_body, u_request->binary_body_length, 0, NULL);
    if (!validate_callback(j_callback, punica))
    {
        if (j_callback != NULL)
        {
            json_decref(j_callback);
        }

        ulfius_set_empty_body_response(u_response, HTTP_400_BAD_REQUEST);
        return U_CALLBACK_COMPLETE;
    }

    callback_url = json_string_value(json_object_get(j_callback, "url"));
    log_message(LOG_LEVEL_INFO, "[SET-CALLBACK] url=%s\n", callback_url);

    punica_lock(punica);

    if (punica->j_callback != NULL)
    {
        json_decref(punica->j_callback);
        punica->j_callback = NULL;
    }

    punica->j_callback = j_callback;

    ulfius_set_empty_body_response(u_response, HTTP_204_NO_CONTENT);

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_delete_callback_cb(const struct _u_request *u_request,
                                          struct _u_response *u_response,
                                          void *context)
{
    punica_context_t *punica = (punica_context_t *)context;

    punica_lock(punica);

    if (punica->j_callback != NULL)
    {
        log_message(LOG_LEVEL_INFO, "[DELETE-CALLBACK] url=%s\n",
                    json_string_value(json_object_get(punica->j_callback, "url")));

        json_decref(punica->j_callback);
        punica->j_callback = NULL;

        ulfius_set_empty_body_response(u_response, HTTP_204_NO_CONTENT);
    }
    else
    {
        log_message(LOG_LEVEL_WARN, "[DELETE-CALLBACK] No callbacks to delete\n");

        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
    }

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

int rest_notifications_pull_cb(const struct _u_request *u_request,
                               struct _u_response *u_response,
                               void *context)
{
    punica_context_t *punica = (punica_context_t *)context;

    punica_lock(punica);

    json_t *j_body = rest_notifications_json(punica);

    rest_notifications_clear(punica);

    ulfius_set_json_body_response(u_response, HTTP_200_OK, j_body);
    json_decref(j_body);

    punica_unlock(punica);

    return U_CALLBACK_COMPLETE;
}

void rest_notify_registration(punica_context_t *punica, rest_notif_registration_t *reg)
{
    linked_list_add(punica->rest_registrations, reg);
}

void rest_notify_update(punica_context_t *punica, rest_notif_update_t *update)
{
    linked_list_add(punica->rest_updates, update);
}

void rest_notify_deregistration(punica_context_t *punica, rest_notif_deregistration_t *dereg)
{
    linked_list_add(punica->rest_deregistrations, dereg);
}

void rest_notify_timeout(punica_context_t *punica, rest_notif_timeout_t *timeout)
{
    linked_list_add(punica->rest_timeouts, timeout);
}

void rest_notify_async_response(punica_context_t *punica, rest_notif_async_response_t *u_response)
{
    linked_list_add(punica->rest_async_responses, u_response);
}

static json_t *rest_async_response_to_json(rest_async_response_t *async)
{
    json_t *j_async_response = json_object();

    json_object_set_new(j_async_response, "timestamp", json_integer(async->timestamp));
    json_object_set_new(j_async_response, "id", json_string(async->id));
    json_object_set_new(j_async_response, "status", json_integer(async->status));
    json_object_set_new(j_async_response, "payload", json_string(async->payload));

    return j_async_response;
}

static json_t *rest_registration_notification_to_json(rest_notif_registration_t *registration)
{
    json_t *j_registration_notification = json_object();

    json_object_set_new(j_registration_notification, "name", json_string(registration->name));

    return j_registration_notification;
}

static json_t *rest_update_notification_to_json(rest_notif_update_t *update)
{
    json_t *j_update_notification = json_object();

    json_object_set_new(j_update_notification, "name", json_string(update->name));

    return j_update_notification;
}

static json_t *rest_deregistration_notification_to_json(rest_notif_deregistration_t *deregistration)
{
    json_t *j_deregistration_notification = json_object();

    json_object_set_new(j_deregistration_notification, "name", json_string(deregistration->name));

    return j_deregistration_notification;
}

json_t *rest_notifications_json(punica_context_t *punica)
{
    json_t *j_notifications;
    json_t *j_array;
    linked_list_entry_t *entry;
    rest_notif_registration_t *reg;
    rest_notif_update_t *upd;
    rest_notif_deregistration_t *dereg;
    rest_notif_async_response_t *async;

    j_notifications = json_object();

    if (punica->rest_registrations)
    {
        j_array = json_array();
        for (entry = punica->rest_registrations->head; entry != NULL; entry = entry->next)
        {
            reg = entry->data;
            json_array_append_new(j_array, rest_registration_notification_to_json(reg));
        }
        json_object_set_new(j_notifications, "registrations", j_array);
    }

    if (punica->rest_updates)
    {
        j_array = json_array();
        for (entry = punica->rest_updates->head; entry != NULL; entry = entry->next)
        {
            upd = entry->data;
            json_array_append_new(j_array, rest_update_notification_to_json(upd));
        }
        json_object_set_new(j_notifications, "reg-updates", j_array);
    }

    if (punica->rest_deregistrations)
    {
        j_array = json_array();
        for (entry = punica->rest_deregistrations->head; entry != NULL; entry = entry->next)
        {
            dereg = entry->data;
            json_array_append_new(j_array, rest_deregistration_notification_to_json(dereg));
        }
        json_object_set_new(j_notifications, "de-registrations", j_array);
    }

    if (punica->rest_async_responses)
    {
        j_array = json_array();
        for (entry = punica->rest_async_responses->head; entry != NULL; entry = entry->next)
        {
            async = entry->data;
            json_array_append_new(j_array, rest_async_response_to_json(async));
        }
        json_object_set_new(j_notifications, "async-responses", j_array);
    }

    return j_notifications;
}

void rest_notifications_clear(punica_context_t *punica)
{
    while (punica->rest_registrations->head != NULL)
    {
        rest_notif_registration_t *reg = punica->rest_registrations->head->data;
        linked_list_remove(punica->rest_registrations, reg);
        rest_notif_registration_delete(reg);
    }

    while (punica->rest_updates->head != NULL)
    {
        rest_notif_update_t *upd = punica->rest_updates->head->data;
        linked_list_remove(punica->rest_updates, upd);
        rest_notif_update_delete(upd);
    }

    while (punica->rest_deregistrations->head != NULL)
    {
        rest_notif_deregistration_t *dereg = punica->rest_deregistrations->head->data;
        linked_list_remove(punica->rest_deregistrations, dereg);
        rest_notif_deregistration_delete(dereg);
    }

    while (punica->rest_async_responses->head != NULL)
    {
        rest_notif_async_response_t *async = punica->rest_async_responses->head->data;
        linked_list_remove(punica->rest_async_responses, async);
        rest_async_response_delete(async);
    }
}

