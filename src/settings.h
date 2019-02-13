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

#ifndef SETTINGS_H
#define SETTINGS_H

#include "logging.h"
#include "security.h"
#include "utils.h"

#include <jansson.h>

#include <argp.h>
#include <stdint.h>
#include <string.h>

typedef struct
{
    uint16_t port;
    http_security_settings_t security;
} http_settings_t;

typedef struct
{
    uint16_t port;
    char *database_file;
} coap_settings_t;

typedef struct
{
    http_settings_t http;
    coap_settings_t coap;
    logging_settings_t logging;
} settings_t;

static const settings_t DEFAULT_PUNICA_SETTINGS =
{
    .http = {
        .port = 8888,
        .security = {
            .private_key = NULL,
            .certificate = NULL,
            .private_key_file = NULL,
            .certificate_file = NULL,
            .jwt = {
                .initialized = false,
                .algorithm = JWT_ALG_HS512,
                .secret_key = NULL,
                .secret_key_length = 32,
                .users_list = NULL,
                .expiration_time = 3600,
            },
        },
    },
    .coap = {
        .port = 5555,
        .database_file = NULL,
    },
    .logging = {
        .level = LOG_LEVEL_WARN,
        .timestamp = false,
        .human_readable_timestamp = false,
    },
};

int settings_initialize(settings_t *settings);
int settings_load(settings_t *settings, int argc, char *argv[]);

#endif // SETTINGS_H

