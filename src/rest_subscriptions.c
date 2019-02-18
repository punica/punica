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
#include "punica.h"
#include "rest.h"

#include <string.h>

static *char logging_section = "[REST API]";

typedef struct
{
    punica_context_t *punica;
    rest_async_response_t *response;
} rest_observe_context_t;

static void rest_observe_cb(uint16_t clientID, lwm2m_uri_t *uriP, int count,
                            lwm2m_media_type_t format, uint8_t *data,
                            int dataLength, void *context)
{
    rest_observe_context_t *ctx = (rest_observe_context_t *) context;
    rest_async_response_t *response;

    logging_section = "[LwM2M / OBSERVE RESPONSE] ";
    log_message(LOG_LEVEL_INFO, "%s id=%s count=%d data=%p\n",
                ctx->response->id, count, data);

    response = rest_async_response_clone(ctx->response);
    if (response == NULL)
    {
        log_message(LOG_LEVEL_ERROR,
                    "%s Error! Failed to clone a response.\n",
                    logging_section);
        return;
    }

    /* Where data is NULL, the count parameter represents CoAP error code */
    rest_async_response_set(response,
                            (data == NULL) ? utils_coap_to_http_status(count) : HTTP_200_OK,
                            data, dataLength);

    rest_notify_async_response(ctx->punica, response);
}

static void rest_unobserve_cb(uint16_t clientID, lwm2m_uri_t *uriP,
                              int count, lwm2m_media_type_t format,
                              uint8_t *data, int dataLength, void *context)
{
    rest_observe_context_t *ctx = (rest_observe_context_t *) context;

    logging_section = "[LwM2M / UNOBSERVE RESPONSE] ";
    log_message(LOG_LEVEL_INFO, "%s id=%s\n", ctx->response->id,
                logging_section);

    linked_list_remove(ctx->punica->rest_observations, ctx->response);

    rest_async_response_delete(ctx->response);
    free(ctx);
}

static int rest_subscriptions_put_cb_unsafe(const struct _u_request *u_request,
                                            struct _u_response *u_response,
                                            punica_context_t *punica)
{
    json_t *j_body;
    lwm2m_client_t *client;
    lwm2m_uri_t uri;
    lwm2m_observation_t *target_path;
    rest_observe_context_t *observe_context = NULL;
    const char *name;
    char path[100];
    size_t len;
    int res;

    /*
     * IMPORTANT!!! Error handling is split into two parts:
     * First, validate client request and, in case of an error, fail fast and
     * return any related 4xx code.
     * Second, once the request is validated, start allocating neccessary
     * resources and, in case of an error, jump (goto) to cleanup section at
     * the end of the function.
     */

    /* Find requested client */
    name = u_map_get(u_request->map_url, "name");
    client = utils_find_client(punica->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/subscriptions/%s/", name);

    if (u_request->http_url == NULL
        || strlen(u_request->http_url) >= sizeof(path)
        || len >= sizeof(path))
    {
        log_message(LOG_LEVEL_WARN,
                    "%s(): invalid http request (%s)!\n",
                    __func__, u_request->http_url);
        return U_CALLBACK_ERROR;
    }

    /*
     * this is probaly redundant
     * if there's only one matching ulfius filter
     */
    if (strncmp(path, u_request->http_url, len) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /* Extract and convert resource path */
    strcpy(path, &u_request->http_url[len - 1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /*
     * IMPORTANT!
     * This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    /* Search for existing registrations to prevent duplicates */
    for (target_path = client->observationList;
         target_path != NULL; target_path = target_path->next)
    {
        if (target_path->uri.flag == uri.flag &&
            target_path->uri.objectId == uri.objectId &&
            target_path->uri.instanceId == uri.instanceId &&
            target_path->uri.resourceId == uri.resourceId)
        {
            observe_context = target_path->userData;
            break;
        }
    }

    if (observe_context == NULL)
    {
        /* Create response callback context and async-response */
        observe_context = malloc(sizeof(rest_observe_context_t));
        if (observe_context == NULL)
        {
            goto exit;
        }

        observe_context->punica = punica;
        observe_context->response = rest_async_response_new();
        if (observe_context->response == NULL)
        {
            goto exit;
        }

        res = lwm2m_observe(
                  punica->lwm2m, client->internalID, &uri,
                  rest_observe_cb, observe_context
              );
        if (res != 0)
        {
            goto exit;
        }

        linked_list_add(punica->rest_observations, observe_context->response);
    }

    j_body = json_object();
    json_object_set_new(j_body, "async-response-id",
                        json_string(observe_context->response->id));
    ulfius_set_json_body_response(u_response, HTTP_202_ACCEPTED, j_body);
    json_decref(j_body);

    return U_CALLBACK_COMPLETE;

exit:
    if (err == U_CALLBACK_ERROR)
    {
        if (observe_context != NULL)
        {
            if (observe_context->response != NULL)
            {
                free(observe_context->response);
            }
            free(observe_context);
        }
    }

    return err;
}

int rest_subscriptions_put_cb(const struct _u_request *u_request,
                              struct _u_response *u_response,
                              void *context)
{
    punica_context_t *punica = (punica_context_t *) context;
    int return_code;

    punica_lock(punica);
    return_code =
        rest_subscriptions_put_cb_unsafe(u_request, u_response, punica);
    punica_unlock(punica);

    return return_code;
}

static int rest_subscriptions_delete_cb_unsafe(
    const struct _u_request *u_request,
    struct _u_response *u_response,
    punica_context_t *punica)
{
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    lwm2m_observation_t *target_path;
    rest_observe_context_t *observe_context = NULL;
    int res;

    /*
     * IMPORTANT!!! Error handling is split into two parts:
     * First, validate client request and, in case of an error,
     * fail fast and return any related 4xx code.
     * Second, once the request is validated, start allocating neccessary
     * resources and, in case of an error, jump (goto) to cleanup section at
     * the end of the function.
     */

    /* Find requested client */
    name = u_map_get(u_request->map_url, "name");
    client = utils_find_client(punica->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/subscriptions/%s/", name);

    if (u_request->http_url == NULL
        || strlen(u_request->http_url) >= sizeof(path) ||
        len >= sizeof(path))
    {
        log_message(LOG_LEVEL_WARN,
                    "%s(): invalid http request (%s)!\n",
                    __func__, u_request->http_url);
        return U_CALLBACK_ERROR;
    }

    /*
     * this is probaly redundant
     * if there's only one matching ulfius filter
     */
    if (strncmp(path, u_request->http_url, len) != 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /* Extract and convert resource path */
    strcpy(path, &u_request->http_url[len - 1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /* Search existing registrations to confirm existing observation */
    for (target_path = client->observationList;
         target_path != NULL; target_path = target_path->next)
    {
        if (target_path->uri.flag == uri.flag &&
            target_path->uri.objectId == uri.objectId &&
            target_path->uri.instanceId == uri.instanceId &&
            target_path->uri.resourceId == uri.resourceId)
        {
            observe_context = target_path->userData;
            break;
        }
    }

    if (observe_context == NULL)
    {
        ulfius_set_empty_body_response(u_response, HTTP_404_NOT_FOUND);
        return U_CALLBACK_COMPLETE;
    }

    /*
     * IMPORTANT!
     * This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    res = lwm2m_observe_cancel(
              punica->lwm2m, client->internalID, &uri,
              rest_unobserve_cb, observe_context
          );

    if (res == COAP_404_NOT_FOUND)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s LwM2M server and client subscriptions mismatch!",
                    logging_section);
    }
    else if (res != 0)
    {
        goto exit;
    }

    ulfius_set_empty_body_response(u_response, HTTP_204_NO_CONTENT);

    return U_CALLBACK_COMPLETE;

exit:

    return err;
}

int rest_subscriptions_delete_cb(const struct _u_request *u_request,
                                 struct _u_response *u_response,
                                 void *context)
{
    punica_context_t *punica = (punica_context_t *) context;
    int return_code;

    punica_lock(punica);
    return_code =
        rest_subscriptions_delete_cb_unsafe(u_request, u_response, punica);
    punica_unlock(punica);

    return return_code;
}
