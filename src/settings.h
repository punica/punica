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

#include <stdint.h>
#include <string.h>
#include <jansson.h>
#include <argp.h>

#include "logging.h"
#include "security.h"
#include "rest-utils.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
#define DATABASE_ALL_KEYS_SET       0x7

typedef struct
{
    uint16_t port;
    http_security_settings_t security;
} http_settings_t;

typedef struct
{
    uint16_t port;
    char *database_file;
    device_database_t *security;
} coap_settings_t;

typedef struct
{
    http_settings_t http;
    coap_settings_t coap;
    logging_settings_t logging;
} settings_t;

error_t parse_opt(int key, char *arg, struct argp_state *state);

int settings_init(int argc, char *argv[], settings_t *settings);

#endif // SETTINGS_H

