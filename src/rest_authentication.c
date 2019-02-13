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

#include "rest_authentication.h"
#include "http_codes.h"
#include "logging.h"
#include "security.h"

#include <string.h>

static char *logging_section = "[JWT]";

static int validate_authentication_body(json_t *j_authentication_body)
{
    json_t *j_name, *j_secret;
    const char *user_name, *user_secret;
    size_t user_name_length, user_secret_length;

    if (j_authentication_body == NULL)
    {
        return 1;
    }

    if (!json_is_object(j_authentication_body)
        || json_object_size(j_authentication_body) != 2)
    {
        return 1;
    }

    j_name = json_object_get(j_authentication_body, "name");
    j_secret = json_object_get(j_authentication_body, "secret");

    if (!json_is_string(j_name) || !json_is_string(j_secret))
    {
        return 1;
    }

    user_name = json_string_value(j_name);
    user_secret = json_string_value(j_secret);

    user_name_length = strnlen(user_name, J_MAX_LENGTH_USER_NAME);
    user_secret_length = strnlen(user_secret, J_MAX_LENGTH_USER_SECRET);

    if (user_name_length == 0 || user_name_length == J_MAX_LENGTH_USER_NAME
        || user_secret_length == 0 || user_secret_length == J_MAX_LENGTH_USER_SECRET)
    {
        return 1;
    }

    return 0;
}

static char *get_request_access_token(const struct _u_request *u_request)
{
    char *token;
    const char *authorization_header = u_map_get(u_request->map_header, HEADER_AUTHORIZATION);

    if (authorization_header == NULL)
    {
        return NULL;
    }

    if (strncmp(authorization_header, HEADER_PREFIX_BEARER, strlen(HEADER_PREFIX_BEARER)) != 0)
    {
        return NULL;
    }

    token = (char *) authorization_header + strlen(HEADER_PREFIX_BEARER);

    return token;
}

static char *get_request_scope(const struct _u_request *u_request)
{
    char *scope;
    size_t method_length = strnlen(u_request->http_verb, J_MAX_LENGTH_METHOD);
    size_t url_length = strnlen(u_request->http_url, J_MAX_LENGTH_URL);

    if (method_length == 0 || method_length == J_MAX_LENGTH_METHOD || url_length == J_MAX_LENGTH_URL)
    {
        return NULL;
    }

    scope = malloc(method_length + url_length + 2);

    if (scope == NULL)
    {
        return NULL;
    }

    strcpy(scope, u_request->http_verb);
    strcat(scope, " ");
    strcat(scope, u_request->http_url);

    return scope;
}

static jwt_error_t validate_token_grants(jwt_settings_t *settings, json_t *j_token)
{
    time_t current_time = time(NULL);
    json_int_t expiration_time;
    json_t *j_issuing_time, *j_user_name;
    const char *user_name;
    size_t user_name_length;

    j_user_name = json_object_get(j_token, "name");
    if (j_user_name == NULL)
    {
        log_message(LOG_LEVEL_TRACE, "[JWT] User is not specified in access token\n");
        return J_ERROR_INVALID_TOKEN;
    }
    else if (!json_is_string(j_user_name))
    {
        log_message(LOG_LEVEL_TRACE, "[JWT] Name specified in token must be string\n");
        return J_ERROR_INVALID_TOKEN;
    }

    user_name = json_string_value(j_user_name);
    user_name_length = strnlen(user_name, J_MAX_LENGTH_USER_NAME);
    if (user_name_length == 0 || user_name_length == J_MAX_LENGTH_USER_NAME)
    {
        log_message(LOG_LEVEL_TRACE, "[JWT] Name specified in token length is invalid\n");
        return J_ERROR_INVALID_TOKEN;
    }

    j_issuing_time = json_object_get(j_token, "iat");
    if (j_issuing_time == NULL)
    {
        log_message(LOG_LEVEL_TRACE, "[JWT] Token issuing time is unspecified\n");
        return J_ERROR_INVALID_TOKEN;
    }

    expiration_time = json_integer_value(j_issuing_time) + settings->expiration_time;

    if (current_time >= expiration_time)
    {
        log_message(LOG_LEVEL_TRACE, "[JWT] User \"%s\" submitted expired token\n",
                    json_string_value(j_user_name));
        return J_ERROR_EXPIRED_TOKEN;
    }

    return J_OK;
}

static jwt_error_t access_token_check_scope(char *access_token,
                                            jwt_settings_t *jwt_settings,
                                            char *required_scope)
{
    char *grants_string;
    const char *user_name;
    json_t *j_grants;
    linked_list_entry_t *entry;
    user_t *user = NULL, *user_entry;
    jwt_t *jwt;
    jwt_error_t status;

    if (jwt_settings == NULL)
    {
        return J_ERROR_INTERNAL;
    }

    if (access_token == NULL)
    {
        return J_ERROR_INVALID_REQUEST;
    }

    status = J_ERROR_INVALID_TOKEN;
    if (jwt_decode(&jwt, access_token,
                   jwt_settings->secret_key, jwt_settings->secret_key_length))
    {
        return status;
    }

    grants_string = jwt_get_grants_json(jwt, NULL);
    if (grants_string == NULL)
    {
        jwt_free(jwt);
        return status;
    }
    j_grants = json_loads(grants_string, JSON_DECODE_ANY, NULL);

    if (j_grants == NULL)
    {
        goto exit;
    }

    status = validate_token_grants(jwt_settings, j_grants);
    if (status != J_OK)
    {
        goto exit;
    }

    user_name = json_string_value(json_object_get(j_grants, "name"));
    for (entry = jwt_settings->users_list->head;
         entry != NULL; entry = entry->next)
    {
        user_entry = entry->data;

        if (strncmp(user_entry->name, user_name,
                    strnlen(user_name, J_MAX_LENGTH_USER_NAME)) == 0)
        {
            user = user_entry;
            break;
        }
    }

    status = J_ERROR_INSUFFICIENT_SCOPE;
    if (user == NULL)
    {
        goto exit;
    }

    if (security_user_check_scope(user, required_scope) != 0)
    {
        goto exit;
    }

    status = J_OK;

exit:
    free(grants_string);
    jwt_free(jwt);
    return status;
}

int rest_authenticate_cb(const struct _u_request *u_request,
                         struct _u_response *u_response,
                         void *context)
{
    json_t *j_request_body, *j_response_body;
    jwt_t *jwt = NULL;
    jwt_settings_t *jwt_settings = (jwt_settings_t *)context;
    linked_list_entry_t *entry;
    user_t *user = NULL, *user_entry;
    char *token;
    const char *user_name, *user_secret;
    time_t issuing_time;
    int status = U_CALLBACK_COMPLETE;

    j_request_body = json_loadb(u_request->binary_body,
                                u_request->binary_body_length, 0, NULL);
    j_response_body = json_object();

    if (validate_authentication_body(j_request_body) != 0)
    {
        log_message(LOG_LEVEL_INFO,
                    "%s Invalid authentication request body\n", logging_section);

        json_object_set_new(j_response_body, "error", json_string("invalid_request"));

        ulfius_set_json_body_response(u_response, HTTP_400_BAD_REQUEST, j_response_body);

        goto exit;
    }

    user_name = json_string_value(json_object_get(j_request_body, "name"));
    user_secret = json_string_value(json_object_get(j_request_body, "secret"));

    for (entry = jwt_settings->users_list->head; entry != NULL; entry = entry->next)
    {
        user_entry = entry->data;

        if (strlen(user_entry->name) == strlen(user_name)
            && strlen(user_entry->secret) == strlen(user_secret)
            && strncmp(user_entry->name, user_name, strlen(user_name)) == 0
            && strncmp(user_entry->secret, user_secret, strlen(user_secret)) == 0)
        {
            user = user_entry;
            break;
        }
    }

    if (user == NULL)
    {
        log_message(LOG_LEVEL_TRACE,
                    "%s User \"%s\" failed to authenticate\n",
                    logging_section, user_name);

        json_object_set_new(j_response_body,
                            "error", json_string("invalid_client"));

        ulfius_set_json_body_response(u_response,
                                      HTTP_400_BAD_REQUEST, j_response_body);

        goto exit;
    }

    if (jwt_new(&jwt) != 0)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s Unable to create new JWT object\n", logging_section);
        status = U_ERROR;
        goto exit;
    }

    time(&issuing_time);

    jwt_set_alg(jwt, jwt_settings->algorithm, jwt_settings->secret_key,
                jwt_settings->secret_key_length);

    jwt_add_grant(jwt, "name", user->name);
    jwt_add_grant_int(jwt, "iat", (long) issuing_time);

    token = jwt_encode_str(jwt);

    json_object_set_new(j_response_body, "access_token", json_string(token));
    json_object_set_new(j_response_body,
                        "expires_in", json_integer(jwt_settings->expiration_time));

    log_message(LOG_LEVEL_INFO,
                "%s Access token issued to user \"%s\".\n",
                logging_section, user->name);

    ulfius_set_json_body_response(u_response,
                                  HTTP_201_CREATED, j_response_body);

exit:
    if (j_request_body != NULL)
    {
        json_decref(j_request_body);
    }
    if (j_response_body != NULL)
    {
        json_decref(j_response_body);
    }
    if (jwt != NULL)
    {
        free(jwt);
    }

    return status;
}

int rest_validate_jwt_cb(const struct _u_request *u_request,
                         struct _u_response *u_response,
                         void *context)
{
    jwt_settings_t *jwt_settings = (jwt_settings_t *)context;
    jwt_error_t token_scope_status;
    char *access_token, *required_scope;

    if (!jwt_settings->initialized)
    {
        return U_CALLBACK_CONTINUE;
    }

    required_scope = get_request_scope(u_request);
    if (required_scope == NULL)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s Failed to obtain request scope", logging_section);
        return U_CALLBACK_ERROR;
    }

    access_token =  get_request_access_token(u_request);

    token_scope_status = access_token_check_scope(
                             access_token, jwt_settings, required_scope);
    free(required_scope);

    switch (token_scope_status)
    {
    case J_OK:
        return U_CALLBACK_CONTINUE;
    case J_ERROR_INVALID_REQUEST:
        u_map_put(u_response->map_header,
                  HEADER_UNAUTHORIZED, ERROR_DESCRIPTION_INVALID_TOKEN);
        return U_CALLBACK_UNAUTHORIZED;
    case J_ERROR_INVALID_TOKEN:
    case J_ERROR_EXPIRED_TOKEN:
        u_map_put(u_response->map_header,
                  HEADER_UNAUTHORIZED, ERROR_DESCRIPTION_INVALID_SCOPE);
        return U_CALLBACK_UNAUTHORIZED;
    case J_ERROR_INSUFFICIENT_SCOPE:
        u_map_put(u_response->map_header,
                  HEADER_UNAUTHORIZED, ERROR_DESCRIPTION_INSUFFICIENT_SCOPE);
        return U_CALLBACK_UNAUTHORIZED;
    case J_ERROR:
    case J_ERROR_INTERNAL:
    default:
        return U_CALLBACK_ERROR;
    }

    return U_CALLBACK_CONTINUE;
}
