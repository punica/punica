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

#ifndef SECURITY_H
#define SECURITY_H

#include "linked_list.h"

#include <jwt.h>
#include <ulfius.h>

#include <stdbool.h>
#include <stdint.h>

enum
{
    J_MAX_LENGTH_SECRET_KEY = 1024,
    J_MAX_LENGTH_METHOD = 8,
    J_MAX_LENGTH_URL = 2048,
    J_MAX_LENGTH_USER_NAME = 1024,
    J_MAX_LENGTH_USER_SECRET = 1024,
};

typedef enum
{
    J_OK,
    J_ERROR,
    J_ERROR_INTERNAL,
    J_ERROR_INVALID_REQUEST,
    J_ERROR_INVALID_TOKEN,
    J_ERROR_EXPIRED_TOKEN,
    J_ERROR_INSUFFICIENT_SCOPE
} jwt_error_t;

typedef struct
{
    char *name;
    char *secret;
    json_t *j_scope_list;
} user_t;

typedef struct
{
    bool initialized;
    jwt_alg_t algorithm;
    unsigned char *secret_key;
    size_t secret_key_length;
    linked_list_t *users_list;
    json_int_t expiration_time;
} jwt_settings_t;

typedef struct
{
    char *private_key;
    char *certificate;
    char *private_key_file;
    char *certificate_file;
    jwt_settings_t jwt;
} http_security_settings_t;

int security_load(http_security_settings_t *settings);
int security_unload(http_security_settings_t *settings);

void jwt_initialize(jwt_settings_t *settings);
void jwt_load(jwt_settings_t *settings);
void jwt_unload(jwt_settings_t *settings);
void jwt_terminate(jwt_settings_t *settings);

user_t *security_user_new();
int security_user_set(user_t *user, const char *name,
                      const char *secret, json_t *j_scope);
void security_user_delete(user_t *user);

int security_user_check_scope(user_t *user, char *required_scope);

#endif // SECURITY_H
