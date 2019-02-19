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

#include "../logging.h"
#include "../punica_core.h"

typedef struct
{
    punica_core_t *punica;
    rest_async_response_t *response;
} rest_observe_context_t;

static void rest_observe_cb(uint16_t clientID, lwm2m_uri_t *uriP, int count,
                            lwm2m_media_type_t format, uint8_t *data, int dataLength,
                            void *context)
{
    rest_observe_context_t *ctx = (rest_observe_context_t *)context;
    rest_async_response_t *response;

    log_message(LOG_LEVEL_INFO, "[OBSERVE-RESPONSE] id=%s count=%d data=%p\n",
                ctx->response->id, count, data);

    response = rest_async_response_clone(ctx->response);
    if (response == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "[OBSERVE-RESPONSE] Error! Failed to clone a response.\n");
        return;
    }

    // Where data is NULL, the count parameter represents CoAP error code
    rest_async_response_set(response,
                            (data == NULL) ? coap_to_http_status(count) : HTTP_200_OK,
                            data, dataLength);

    rest_notify_async_response(ctx->punica, response);
}

static void rest_unobserve_cb(uint16_t clientID, lwm2m_uri_t *uriP, int count,
                              lwm2m_media_type_t format, uint8_t *data, int dataLength,
                              void *context)
{
    rest_observe_context_t *ctx = (rest_observe_context_t *)context;

    log_message(LOG_LEVEL_INFO, "[UNOBSERVE-RESPONSE] id=%s\n", ctx->response->id);

    linked_list_remove(ctx->punica->observeList, ctx->response);

    rest_async_response_delete(ctx->response);
    free(ctx);
}

static int rest_subscriptions_put_cb_unsafe(punica_core_t *punica,
                                            const ulfius_req_t *req,
                                            ulfius_resp_t *resp)
{
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    json_t *jresponse;
    lwm2m_observation_t *targetP;
    rest_observe_context_t *observe_context = NULL;
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
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(punica->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/subscriptions/%s/", name);

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

    // Search for existing registrations to prevent duplicates
    for (targetP = client->observationList; targetP != NULL; targetP = targetP->next)
    {
        if (targetP->uri.flag == uri.flag &&
            targetP->uri.objectId == uri.objectId &&
            targetP->uri.instanceId == uri.instanceId &&
            targetP->uri.resourceId == uri.resourceId)
        {
            observe_context = targetP->userData;
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

        linked_list_add(punica->observeList, observe_context->response);
    }

    jresponse = json_object();
    json_object_set_new(jresponse, "async-response-id", json_string(observe_context->response->id));
    ulfius_set_json_body_response(resp, 202, jresponse);
    json_decref(jresponse);

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

int rest_subscriptions_put_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    punica_core_t *punica = (punica_core_t *)context;
    int ret;

    rest_lock(punica);
    ret = rest_subscriptions_put_cb_unsafe(punica, req, resp);
    rest_unlock(punica);

    return ret;
}

static int rest_subscriptions_delete_cb_unsafe(punica_core_t *punica,
                                               const ulfius_req_t *req,
                                               ulfius_resp_t *resp)
{
    const char *name;
    lwm2m_client_t *client;
    char path[100];
    size_t len;
    lwm2m_uri_t uri;
    lwm2m_observation_t *targetP;
    rest_observe_context_t *observe_context = NULL;
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
    name = u_map_get(req->map_url, "name");
    client = rest_endpoints_find_client(punica->lwm2m->clientList, name);
    if (client == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /* Reconstruct and validate client path */
    len = snprintf(path, sizeof(path), "/subscriptions/%s/", name);

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

    /* Search existing registrations to confirm existing observation */
    for (targetP = client->observationList; targetP != NULL; targetP = targetP->next)
    {
        if (targetP->uri.flag == uri.flag &&
            targetP->uri.objectId == uri.objectId &&
            targetP->uri.instanceId == uri.instanceId &&
            targetP->uri.resourceId == uri.resourceId)
        {
            observe_context = targetP->userData;
            break;
        }
    }

    if (observe_context == NULL)
    {
        ulfius_set_empty_body_response(resp, 404);
        return U_CALLBACK_COMPLETE;
    }

    /*
     * IMPORTANT! This is where server-error section starts and any error must
     * go through the cleanup section. See comment above.
     */
    const int err = U_CALLBACK_ERROR;

    // using dummy callback (rest_unobserve_cb), because NULL callback causes segmentation fault
    res = lwm2m_observe_cancel(
              punica->lwm2m, client->internalID, &uri,
              rest_unobserve_cb, observe_context
          );

    if (res == COAP_404_NOT_FOUND)
    {
        log_message(LOG_LEVEL_WARN, "[WARNING] LwM2M and restserver subscriptions mismatch!");
    }
    else if (res != 0)
    {
        goto exit;
    }

    ulfius_set_empty_body_response(resp, 204);

    return U_CALLBACK_COMPLETE;

exit:

    return err;
}

int rest_subscriptions_delete_cb(const ulfius_req_t *req, ulfius_resp_t *resp, void *context)
{
    punica_core_t *punica = (punica_core_t *)context;
    int ret;

    rest_lock(punica);
    ret = rest_subscriptions_delete_cb_unsafe(punica, req, resp);
    rest_unlock(punica);

    return ret;
}
