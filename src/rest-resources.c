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
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <linux/random.h>

#include "logging.h"
#include "punica_core.h"

typedef struct
{
    punica_core_t *punica;
    uint8_t *payload;
    rest_async_response_t *response;
} rest_async_context_t;

static int http_to_coap_format(const char *type)
{
    if (type == NULL)
    {
        return -1;
    }

    if (strcmp(type, "application/vnd.oma.lwm2m+tlv") == 0)
    {
        return LWM2M_CONTENT_TLV;
    }

    if (strcmp(type, "application/vnd.oma.lwm2m+json") == 0)
    {
        return LWM2M_CONTENT_JSON;
    }

    if (strcmp(type, "application/octet-stream") == 0)
    {
        return LWM2M_CONTENT_OPAQUE;
    }

    return -1;
}

static void rest_async_cb(uint16_t clientID, lwm2m_uri_t *uriP, int status,
                          lwm2m_media_type_t format, uint8_t *data, int dataLength,
                          void *context)
{
    rest_async_context_t *ctx = (rest_async_context_t *)context;
    int err;

    log_message(LOG_LEVEL_INFO, "[ASYNC-RESPONSE] id=%s status=%d\n",
                ctx->response->id, coap_to_http_status(status));

    rest_list_remove(ctx->punica->pendingResponseList, ctx->response);

    err = rest_async_response_set(ctx->response, coap_to_http_status(status), data, dataLength);
    assert(err == 0);

    rest_notify_async_response(ctx->punica, ctx->response);

    // Free rest_async_context_t which was allocated in rest_resources_read_cb
    if (ctx->payload != NULL)
    {
        free(ctx->payload);
    }

    free(ctx);
}

static int rest_resources_rwe_cb_unsafe(punica_core_t *punica,
                                        const ulfius_req_t *req, ulfius_resp_t *resp)
{
    enum
    {
        RES_ACTION_UNDEFINED,
        RES_ACTION_READ,
        RES_ACTION_WRITE,
        RES_ACTION_EXEC,
    } action = RES_ACTION_UNDEFINED;
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    json_t *jresponse;
    rest_async_context_t *async_context = NULL;
    lwm2m_media_type_t format;
    int res;

    /*
     * IMPORTANT!!! Error handling is split into two parts:
     * First, validate client request and, in case of an error, fail fast and
     * return any related 4xx code.
     * Second, once the request is validated, start allocating neccessary
     * resources and, in case of an error, jump (goto) to cleanup section at
     * the end of the function.
     */

    if (strcmp(req->http_verb, "GET") == 0)
    {
        log_message(LOG_LEVEL_INFO, "[READ-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_READ;
    }
    else if (strcmp(req->http_verb, "PUT") == 0)
    {
        log_message(LOG_LEVEL_INFO, "[WRITE-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_WRITE;
    }
    else if (strcmp(req->http_verb, "POST") == 0)
    {
        log_message(LOG_LEVEL_INFO, "[EXEC-REQUEST] %s\n", req->http_url);
        action = RES_ACTION_EXEC;
    }
    else
    {
        ulfius_set_empty_body_response(resp, 405);
        return U_CALLBACK_COMPLETE;
    }

    if (action == RES_ACTION_WRITE)
    {
        format = http_to_coap_format(u_map_get_case(req->map_header, "Content-Type"));
        if (format == -1)
        {
            ulfius_set_empty_body_response(resp, 415);
            return U_CALLBACK_COMPLETE;
        }
    }
    else if (action == RES_ACTION_EXEC)
    {
        if ((u_map_get_case(req->map_header, "Content-Type") == NULL)
            || (strcmp(u_map_get_case(req->map_header, "Content-Type"), "text/plain") == 0))
        {
            format = LWM2M_CONTENT_TEXT;
        }
        else
        {
            ulfius_set_empty_body_response(resp, 415);
            return U_CALLBACK_COMPLETE;
        }
    }

    // Return 400 BAD REQUEST if request body length is 0
    if ((action == RES_ACTION_WRITE) && (req->binary_body_length == 0))
    {
        ulfius_set_empty_body_response(resp, 400);
        return U_CALLBACK_COMPLETE;
    }

    /* Find requested client */
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(punica->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 410);
        return U_CALLBACK_COMPLETE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/endpoints/%s/", name);

    if (req->http_url == NULL || strlen(req->http_url) >= sizeof(path) || len >= sizeof(path))
    {
        log_message(LOG_LEVEL_WARN, "%s(): invalid http request (%s)!\n", __func__, req->http_url);
        return U_CALLBACK_ERROR;
    }

    // this is probaly redundant if there's only one matching ulfius filter
    if (strncmp(path, req->http_url, len) != 0)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /* Extract and convert resource path */
    strcpy(path, &req->http_url[len - 1]);

    if (lwm2m_stringToUri(path, strlen(path), &uri) == 0)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /*
     * IMPORTANT! This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    /* Create response callback context and async response */
    async_context = malloc(sizeof(rest_async_context_t));
    if (async_context == NULL)
    {
        goto exit;
    }

    async_context->punica = punica;

    async_context->payload = malloc(req->binary_body_length);
    if (async_context->payload == NULL)
    {
        goto exit;
    }
    memcpy(async_context->payload, req->binary_body, req->binary_body_length);

    async_context->response = rest_async_response_new();
    if (async_context->response == NULL)
    {
        goto exit;
    }

    switch (action)
    {
    case RES_ACTION_READ:
        res = lwm2m_dm_read(
                  punica->lwm2m, client->internalID, &uri,
                  rest_async_cb, async_context
              );
        break;

    case RES_ACTION_WRITE:
        res = lwm2m_dm_write(
                  punica->lwm2m, client->internalID, &uri,
                  format, async_context->payload, req->binary_body_length,
                  rest_async_cb, async_context
              );
        break;

    case RES_ACTION_EXEC:
        res = lwm2m_dm_execute(
                  punica->lwm2m, client->internalID, &uri,
                  format, async_context->payload, req->binary_body_length,
                  rest_async_cb, async_context
              );
        break;

    default:
        assert(false); // if this happens, there's an error in the logic
        break;
    }

    if (res != 0)
    {
        goto exit;
    }
    rest_list_add(punica->pendingResponseList, async_context->response);

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(async_context->response->id));
    ulfius_set_json_body_response(resp, 202, jresponse);
    json_decref(jresponse);

    return U_CALLBACK_COMPLETE;

exit:
    if (err == U_CALLBACK_ERROR)
    {
        if (async_context != NULL)
        {
            if (async_context->payload != NULL)
            {
                free(async_context->payload);
            }

            if (async_context->response != NULL)
            {
                free(async_context->response);
            }

            free(async_context);
        }
    }

    return err;
}

int rest_resources_rwe_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    punica_core_t *punica = (punica_core_t *)context;
    int ret;

    rest_lock(punica);
    ret = rest_resources_rwe_cb_unsafe(punica, req, resp);
    rest_unlock(punica);

    return ret;
}

