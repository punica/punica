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

#include "settings.h"

#include "linked_list.h"
#include "rest_core_types.h"
#include "security.h"
#include "utils.h"
#include "version.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_PSK_KEY_BIT        0x2
#define DATABASE_PSK_ID_KEY_BIT     0x4
#define DATABASE_ALL_KEYS_SET       0x7

const char *argp_program_version = PUNICA_FULL_VERSION;

static char *logging_section = "[SETTINGS]";

static char description[] =
    "Punica - interface to LwM2M server and all clients connected to it";

static struct argp_option options[] =
{
    {"log", 'l', "LOGGING_LEVEL", 0, "Specify logging level (0-5)"},
    {"config", 'c', "FILE", 0, "Specify parameters configuration file"},
    {"database", 'd', "FILE", 0, "Specify device database file"},
    {"private_key", 'k', "FILE", 0, "Specify TLS security private key"},
    {"certificate", 'C', "FILE", 0, "Specify TLS security certificate"},
    {0}
};

static void set_coap_settings(json_t *j_section, coap_settings_t *settings)
{
    const char *key, *section_name = "coap";
    json_t *j_value;

    logging_section = "[SETTINGS / CoAP]";

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(j_value);
        }
        else if (strcasecmp(key, "database_file") == 0)
        {
            if (json_is_string(j_value))
            {
                settings->database_file = (char *) json_string_value(j_value);
            }
            else
            {
                log_message(LOG_LEVEL_WARN,
                            "%s value at key %s:%s must be a string",
                            logging_section, section_name, key);
            }
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file key: %s.%s\n",
                        logging_section, section_name, key);
        }
    }
}

static int set_user_settings(json_t *j_user_settings,
                             linked_list_t *users_list)
{
    user_t *user, *user_entry;
    linked_list_entry_t *entry;
    json_t *j_name, *j_secret, *j_scope, *j_scope_value;
    const char *user_name, *user_secret;
    char *scope_value;
    size_t user_name_length, user_secret_length, scope_length, scope_index;

    j_name = json_object_get(j_user_settings, "name");
    j_secret = json_object_get(j_user_settings, "secret");
    j_scope = json_object_get(j_user_settings, "scope");

    if (!json_is_string(j_name)
        || strlen(json_string_value(j_name)) < 1)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s User configured without name.\n",
                    logging_section);
        return 1;
    }

    user_name = json_string_value(j_name);
    user_name_length = strnlen(user_name, J_MAX_LENGTH_USER_NAME);

    if (user_name_length == 0
        || user_name_length == J_MAX_LENGTH_USER_NAME)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s User name length is invalid.\n", logging_section);
        return 1;
    }

    for (entry = users_list->head; entry != NULL; entry = entry->next)
    {
        user_entry = entry->data;

        if (strncmp(user_entry->name, user_name,
                    J_MAX_LENGTH_USER_NAME) == 0)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Found duplicate \"%s\" user name in config.\n",
                        logging_section, user_name);
            return 1;
        }
    }

    if (!json_is_string(j_secret))
    {
        log_message(LOG_LEVEL_WARN,
                    "%s User \"%s\" configured without valid secret key.\n",
                    logging_section, user_name);
        return 1;
    }

    user_secret = json_string_value(j_secret);
    user_secret_length = strnlen(user_secret, J_MAX_LENGTH_USER_SECRET);
    if (user_secret_length == J_MAX_LENGTH_USER_NAME)
    {
        log_message(LOG_LEVEL_WARN,
                    "%s User secret length is invalid.\n", logging_section);
        return 1;
    }

    if (!json_is_array(j_scope))
    {
        log_message(LOG_LEVEL_WARN,
                    "%s User \"%s\" scope list %s.\n",
                    logging_section, user_name,
                    "contains invalid scope");
        log_message(LOG_LEVEL_WARN,
                    "%s Setting default scope: \"[]\".\n", logging_section);
        j_scope = json_array();
    }

    json_array_foreach(j_scope, scope_index, j_scope_value)
    {
        if (!json_is_string(j_scope_value))
        {
            log_message(LOG_LEVEL_WARN,
                        "%s User \"%s\" scope list %s.\n",
                        logging_section, user_name,
                        "contains invalid type value");
            return 1;
        }

        scope_value = (char *) json_string_value(j_scope_value);
        scope_length = strnlen(scope_value,
                               J_MAX_LENGTH_METHOD + 1 + J_MAX_LENGTH_URL);
        if (scope_length == 0
            || scope_length == J_MAX_LENGTH_METHOD + 1 + J_MAX_LENGTH_URL)
        {
            log_message(LOG_LEVEL_WARN,
                        "%s User \"%s\" scope list %s.\n",
                        logging_section, user_name,
                        "contains invalid length value");
            return 1;
        }
    }

    user = security_user_new();

    security_user_set(user, user_name, user_secret, j_scope);

    linked_list_add(users_list, user);

    return 0;
}

static void set_jwt_settings(json_t *j_section, jwt_settings_t *settings)
{
    size_t user_index, value_length;
    const char *key, *string_value;
    const char *section_name = "http.security.jwt";
    json_t *j_value, *j_user_settings;
    jwt_initialize(settings);

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "algorithm") == 0)
        {
            settings->algorithm = jwt_str_alg(json_string_value(j_value));
        }
        else if (strcasecmp(key, "expiration_time") == 0)
        {
            if (json_is_integer(j_value))
            {
                settings->expiration_time = json_integer_value(j_value);
            }
            else
            {
                log_message(LOG_LEVEL_WARN,
                            "%s JWT Token %s must be an integer\n",
                            logging_section, key);
            }
        }
        else if (strcasecmp(key, "secret_key") == 0)
        {
            if (!json_is_string(j_value))
            {
                log_message(LOG_LEVEL_WARN,
                            "%s JWT Token %s must be a string\n",
                            logging_section, key);
                continue;
            }

            string_value = json_string_value(j_value);
            value_length = strnlen(string_value, J_MAX_LENGTH_SECRET_KEY);
            if (value_length == 0
                || value_length == J_MAX_LENGTH_SECRET_KEY)
            {
                log_message(LOG_LEVEL_WARN,
                            "%s JWT Token %s length is invalid\n",
                            logging_section, key);
                continue;
            }

            if (settings->secret_key != NULL)
            {
                free(settings->secret_key);
            }

            settings->secret_key_length = value_length;
            settings->secret_key = (unsigned char *) malloc(
                                       settings->secret_key_length * sizeof(unsigned char));
            if (settings->secret_key == NULL)
            {
                log_message(LOG_LEVEL_FATAL,
                            "%s Failed to allocate %s!\n",
                            logging_section, key);
                settings->secret_key_length = 0;
                continue;
            }
            memcpy(settings->secret_key, string_value, value_length);
        }
        else if (strcasecmp(key, "users") == 0)
        {
            if (json_is_array(j_value))
            {
                json_array_foreach(j_value, user_index, j_user_settings)
                {
                    if (json_is_object(j_user_settings))
                    {
                        set_user_settings(j_user_settings,
                                          settings->users_list);
                    }
                    else
                    {
                        log_message(LOG_LEVEL_WARN,
                                    "%s User settings %s.\n",
                                    logging_section,
                                    "must be stored in an object");
                    }
                }
            }
            else
            {
                log_message(LOG_LEVEL_WARN,
                            "%s Users settings %s.\n",
                            logging_section,
                            "must be stored in a list of objects");
            }
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file key: %s.%s\n",
                        logging_section, section_name, key);
        }
    }
}

static void set_http_security_settings(json_t *j_section,
                                       http_security_settings_t *settings)
{
    const char *key;
    const char *section_name = "http.security";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "private_key") == 0)
        {
            settings->private_key = (char *) json_string_value(j_value);
        }
        else if (strcasecmp(key, "certificate") == 0)
        {
            settings->certificate = (char *) json_string_value(j_value);
        }
        else if (strcasecmp(key, "jwt") == 0)
        {
            set_jwt_settings(j_value, &settings->jwt);
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file key: %s.%s\n",
                        logging_section, section_name, key);
        }
    }
}

static void set_http_settings(json_t *j_section, http_settings_t *settings)
{
    const char *key, *section_name = "http";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "port") == 0)
        {
            settings->port = (uint16_t) json_integer_value(j_value);
        }
        else if (strcasecmp(key, "security") == 0)
        {
            set_http_security_settings(j_value, &settings->security);
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file key: %s.%s\n",
                        logging_section, section_name, key);
        }
    }
}

static void set_logging_settings(json_t *j_section,
                                 logging_settings_t *settings)
{
    const char *key;
    const char *section_name = "logging";
    json_t *j_value;

    json_object_foreach(j_section, key, j_value)
    {
        if (strcasecmp(key, "level") == 0)
        {
            settings->level = (logging_level_t) json_integer_value(j_value);
        }
        else if (strcasecmp(key, "timestamp") == 0)
        {
            if (json_is_boolean(j_value))
            {
                settings->timestamp = json_is_true(j_value) ? true : false;
            }
            else
            {
                log_message(LOG_LEVEL_WARN,
                            "%s %s.%s must be set to a boolean value!\n",
                            logging_section, section_name, key);
            }
        }
        else if (strcasecmp(key, "human_readable_timestamp") == 0)
        {
            if (json_is_boolean(j_value))
            {
                settings->human_readable_timestamp =
                    json_is_true(j_value) ? true : false;
            }
            else
            {
                log_message(LOG_LEVEL_WARN,
                            "%s %s.%s must be set to a boolean value!\n",
                            logging_section, section_name, key);
            }
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file key: %s.%s\n",
                        logging_section, section_name, key);
        }
    }
}

static int read_config(char *config_name, settings_t *settings)
{
    json_error_t error;
    const char *section;
    json_t *j_value;

    json_t *j_settings = json_load_file(config_name, 0, &error);

    if (j_settings == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "%s %s:%d:%d error:%s \n",
                    logging_section, config_name, error.line,
                    error.column, error.text);
        return 1;
    }

    json_object_foreach(j_settings, section, j_value)
    {
        if (strcasecmp(section, "coap") == 0)
        {
            set_coap_settings(j_value, &settings->coap);
        }
        else if (strcasecmp(section, "http") == 0)
        {
            set_http_settings(j_value, &settings->http);
        }
        else if (strcasecmp(section, "logging") == 0)
        {
            set_logging_settings(j_value, &settings->logging);
        }
        else
        {
            log_message(LOG_LEVEL_WARN,
                        "%s Unrecognised configuration file section: %s\n",
                        logging_section, section);
        }
    }

    return 0;
}

static error_t parse_arguments(int key, char *arg, struct argp_state *state)
{
    settings_t *settings = state->input;

    switch (key)
    {
    case 'l':
        settings->logging.level = atoi(arg);
        break;

    case 'c':
        if (read_config(arg, settings) != 0)
        {
            argp_usage(state);
            return 1;
        }
        break;

    case 'd':
        settings->coap.database_file = strdup(arg);
        if (settings->coap.database_file == NULL)
        {
            argp_usage(state);
            return 1;
        }
        break;

    case 'C':
        settings->http.security.certificate = arg;
        break;

    case 'k':
        settings->http.security.private_key = arg;
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_arguments, 0, description };


int settings_initialize(settings_t *settings)
{
    *settings = DEFAULT_PUNICA_SETTINGS;
    jwt_settings_t *jwt_settings = &settings->http.security.jwt;

    jwt_settings->users_list = linked_list_new();
    jwt_settings->secret_key = (unsigned char *) malloc(
                                   jwt_settings->secret_key_length * sizeof(unsigned char));

    utils_get_random(jwt_settings->secret_key,
                     jwt_settings->secret_key_length);

    return 0;
}

int settings_load(settings_t *settings, int argc, char *argv[])
{
    return argp_parse(&argp, argc, argv, 0, 0, settings);
}
