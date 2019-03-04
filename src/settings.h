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
#include "plugin_manager/basic_plugin_manager.h"
#include "rest/rest_utils.h"

typedef enum
{
    PUNICA_COAP_MODE_INSECURE,
    PUNICA_COAP_MODE_SECURE,
    PUNICA_COAP_MODE_BOTH
} punica_coap_mode_t;

typedef struct
{
    uint16_t port;
    http_security_settings_t security;
} http_settings_t;

typedef struct
{
    uint16_t security_mode;
    uint16_t port;
    char *private_key_file;
    char *certificate_file;
    char *database_file;
} coap_settings_t;

typedef struct
{
    const char *name;
    const char *path;
} plugin_settings_t;

typedef struct
{
    linked_list_t *plugins_list;
} plugins_settings_t;

typedef struct
{
    http_settings_t http;
    coap_settings_t coap;
    logging_settings_t logging;
    plugins_settings_t plugins;
} settings_t;

error_t parse_opt(int key, char *arg, struct argp_state *state);

int settings_init(int argc, char *argv[], settings_t *settings);

#endif // SETTINGS_H

