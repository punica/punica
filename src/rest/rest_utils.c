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
#include <uuid/uuid.h>

#include "rest_utils.h"

#include "../punica.h"

#define DATABASE_UUID_KEY_BIT       0x1
#define DATABASE_MODE_KEY_BIT       0x2
#define DATABASE_NAME_KEY_BIT       0x4
#define DATABASE_ALL_NEW_KEYS_SET   0x6
#define DATABASE_ALL_KEYS_SET       0x7

typedef struct
{
    uint8_t secret_key[1024];
    size_t secret_key_len;
    uint8_t public_key[1024];
    size_t public_key_len;
    uint8_t server_key[1024];
    size_t server_key_len;
    uint8_t serial[20];
    size_t serial_len;
    char name[128];
} device_new_credentials_t;

static int database_find_existing_entry(const char *name, linked_list_t *device_list)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(name, device_data->name) == 0)
        {
            return 1;
        }
    }

    return 0;
}

static void generate_serial(uint8_t *buffer, size_t *length)
{
    int ret;

    do
    {
        ret = rest_get_random(buffer, 20);
    } while ((buffer[0] >> 7) == 1); // Serial number must be positive

    *length = ret;
}

static int device_new_psk(device_new_credentials_t *device_credentials)
{
    size_t ret;

    memcpy(device_credentials->public_key, device_credentials->name, strlen(device_credentials->name) + 1);
    device_credentials->public_key_len = strlen(device_credentials->name);

    ret = rest_get_random(device_credentials->secret_key, 16);
    if (ret == 0)
    {
        return -1;
    }

    device_credentials->secret_key_len = ret;
    return 0;
}

static int device_new_certificate(device_new_credentials_t *device_credentials, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    gnutls_x509_crt_t device_cert = NULL;
    gnutls_x509_privkey_t device_key = NULL;
    gnutls_x509_crt_t ca_cert = NULL;
    gnutls_x509_privkey_t ca_key = NULL;
    gnutls_datum_t ca_key_buffer = {NULL, 0};
    gnutls_datum_t ca_cert_buffer = {NULL, 0};
    time_t activation_time;
    int ret = -1;

    if (gnutls_x509_crt_init(&device_cert)
        || gnutls_x509_privkey_init(&device_key)
        || gnutls_x509_crt_init(&ca_cert)
        || gnutls_x509_privkey_init(&ca_key))
    {
        goto exit;
    }

    if (gnutls_load_file(rest->settings->coap.certificate_file, &ca_cert_buffer)
        || gnutls_load_file(rest->settings->coap.private_key_file, &ca_key_buffer))
    {
        goto exit;
    }

    if (gnutls_x509_crt_import(ca_cert, &ca_cert_buffer, GNUTLS_X509_FMT_PEM)
        || gnutls_x509_privkey_import(ca_key, &ca_key_buffer, GNUTLS_X509_FMT_PEM))
    {
        goto exit;
    }

    if (gnutls_x509_privkey_generate(device_key, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0))
    {
        goto exit;
    }

    //TODO: check for existing serial
    generate_serial(device_credentials->serial, &device_credentials->serial_len);
    activation_time = time(NULL);

    if (gnutls_x509_crt_set_version(device_cert, 3)
        || gnutls_x509_crt_set_serial(device_cert, device_credentials->serial, device_credentials->serial_len)
        || gnutls_x509_crt_set_activation_time(device_cert, activation_time)
        || gnutls_x509_crt_set_expiration_time(device_cert, activation_time + 60 * 60)
        || gnutls_x509_crt_set_key(device_cert, device_key))
    {
        goto exit;
    }

    if (gnutls_x509_crt_set_subject_alt_name(device_cert, GNUTLS_SAN_DNSNAME, device_credentials->name, strlen(device_credentials->name) + 1, GNUTLS_FSAN_SET))
    {
        goto exit;
    }

    if (gnutls_x509_crt_sign(device_cert, ca_cert, ca_key))
    {
        goto exit;
    }

    if (gnutls_x509_crt_export(device_cert, GNUTLS_X509_FMT_PEM, device_credentials->public_key, &device_credentials->public_key_len)
        || gnutls_x509_crt_export(ca_cert, GNUTLS_X509_FMT_PEM, device_credentials->server_key, &device_credentials->server_key_len)
        || gnutls_x509_privkey_export(device_key, GNUTLS_X509_FMT_PEM, device_credentials->secret_key, &device_credentials->secret_key_len))
    {
        goto exit;
    }

    ret = 0;
exit:
    gnutls_free(ca_cert_buffer.data);
    gnutls_free(ca_key_buffer.data);
    gnutls_x509_crt_deinit(device_cert);
    gnutls_x509_privkey_deinit(device_key);
    gnutls_x509_crt_deinit(ca_cert);
    gnutls_x509_privkey_deinit(ca_key);

    return ret;
}

static int device_populate_credentials(json_t *j_device_object, device_new_credentials_t *device_credentials)
{
    json_t *j_credentials;
    char base64_secret_key[1024] = {0};
    char base64_public_key[1024] = {0};
    char base64_server_key[1024] = {0};
    char base64_serial[1024] = {0};
    size_t base64_length;

    base64_length = sizeof(base64_secret_key);
    if (base64_encode(device_credentials->secret_key, device_credentials->secret_key_len, base64_secret_key, &base64_length))
    {
        return -1;
    }

    base64_length = sizeof(base64_public_key);
    if (base64_encode(device_credentials->public_key, device_credentials->public_key_len, base64_public_key, &base64_length))
    {
        return -1;
    }

    base64_length = sizeof(base64_server_key);
    if (base64_encode(device_credentials->server_key, device_credentials->server_key_len, base64_server_key, &base64_length))
    {
        return -1;
    }

    base64_length = sizeof(base64_serial);
    if (base64_encode(device_credentials->serial, device_credentials->serial_len, base64_serial, &base64_length))
    {
        return -1;
    }

    j_credentials = json_pack("{s:s, s:s, s:s, s:s}", "secret_key", base64_secret_key, "public_key", base64_public_key, "server_key", base64_server_key, "serial", base64_serial);
    if (j_credentials == NULL)
    {
        return -1;
    }

    if (json_object_update_missing(j_device_object, j_credentials))
    {
        json_decref(j_credentials);
        return -1;
    }

    json_decref(j_credentials);
    return 0;
}

static int device_new_credentials(json_t *j_device_object, void *context)
{
    //TODO: needs streamlining/to be moved into sepparate functions
    json_t *j_value;
    const char *j_string;
    device_new_credentials_t device_credentials;

    memset(&device_credentials, 0, sizeof(device_credentials));

    j_value = json_object_get(j_device_object, "name");
    if (j_value == NULL)
    {
        return -1;
    }

    j_string = json_string_value(j_value);
    if (strlen(j_string) > 127) // won't fit into buffer
    {
        return -1;
    }
    memcpy(device_credentials.name, j_string, strlen(j_string) + 1);

    j_value = json_object_get(j_device_object, "mode");
    if (j_value == NULL)
    {
        return -1;
    }
    j_string = json_string_value(j_value);

    if (strcasecmp(j_string, "psk") == 0)
    {
        if (device_new_psk(&device_credentials))
        {
            return -1;
        }
    }
    else if (strcasecmp(j_string, "cert") == 0)
    {
        if (device_new_certificate(&device_credentials, context))
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    if (device_populate_credentials(j_device_object, &device_credentials))
    {
        return -1;
    }

    return 0;
}

int coap_to_http_status(int status)
{
    switch (status)
    {
    case COAP_204_CHANGED:
    case COAP_205_CONTENT:
        return HTTP_200_OK;

    case COAP_404_NOT_FOUND:
        return HTTP_404_NOT_FOUND;

    default:
        return -(((status >> 5) & 0x7) * 100 + (status & 0x1F));
    }
}

void database_free_entry(database_entry_t *device_entry)
{

    if (device_entry)
    {
        if (device_entry->uuid)
        {
            free(device_entry->uuid);
        }
        if (device_entry->public_key)
        {
            free(device_entry->public_key);
        }
        if (device_entry->secret_key)
        {
            free(device_entry->secret_key);
        }

        free(device_entry);
    }
}

int database_validate_new_entry(json_t *j_new_device_object, linked_list_t *device_list)
{
    int key_check = 0;
    const char *key, *value_string;
    json_t *j_value;

    if (!json_is_object(j_new_device_object))
    {
        return -1;
    }

    json_object_foreach(j_new_device_object, key, j_value)
    {
        if (!json_is_string(j_value))
        {
            return -1;
        }

        if (strcasecmp(key, "mode") == 0)
        {
            value_string = json_string_value(j_value);

            if (strcasecmp(value_string, "psk")
                && strcasecmp(value_string, "cert"))
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "name") == 0)
        {
            value_string = json_string_value(j_value);

            if (database_find_existing_entry(value_string, device_list))
            {
                return -1;
            }

            key_check |= DATABASE_NAME_KEY_BIT;
        }
    }

    if (key_check != DATABASE_ALL_NEW_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

int database_validate_entry(json_t *j_device_object)
{
    int key_check = 0;
    const char *key;
    json_t *j_value;
    uint8_t buffer[512];
    size_t buffer_len = sizeof(buffer);

    if (!json_is_object(j_device_object))
    {
        return -1;
    }

    json_object_foreach(j_device_object, key, j_value)
    {
        //TODO: alot more keys now
        if (!json_is_string(j_value))
        {
            return -1;
        }
        if (strcasecmp(key, "uuid") == 0)
        {
            key_check |= DATABASE_UUID_KEY_BIT;
        }
        else if (strcasecmp(key, "psk") == 0)
        {
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
            {
                return -1;
            }
            key_check |= DATABASE_PSK_KEY_BIT;
        }
        else if (strcasecmp(key, "psk_id") == 0)
        {
            if (base64_decode(json_string_value(j_value), buffer, &buffer_len))
            {
                return -1;
            }
            key_check |= DATABASE_PSK_ID_KEY_BIT;
        }
    }

//  function does not check for duplicate keys
    if (key_check != DATABASE_ALL_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

int database_populate_entry(json_t *j_device_object, database_entry_t *device_entry)
{
    //TODO: goto exit
    json_t *j_value;
    const char *json_string;
    int ret = -1;

    if (j_device_object == NULL || device_entry == NULL)
    {
        return -1;
    }

    j_value = json_object_get(j_device_object, "uuid");
    json_string = json_string_value(j_value);

    device_entry->uuid = strdup(json_string);
    if (device_entry->uuid == NULL)
    {
        return -1;
    }


    j_value = json_object_get(j_device_object, "name");
    json_string = json_string_value(j_value);

    device_entry->name = (char *)calloc(1, strlen(json_string) + 1);
    if (device_entry->name == NULL)
    {
        goto exit;
    }
    memcpy(device_entry->name, json_string, strlen(json_string) + 1);


    j_value = json_object_get(j_device_object, "mode");
    json_string = json_string_value(j_value);

    if (strcasecmp(json_string, "psk"))
    {
        device_entry->mode = MODE_PSK;
    }
    else if (strcasecmp(json_string, "cert"))
    {
        device_entry->mode = MODE_CERT;
    }

    //TODO: fill remainder
    j_value = json_object_get(j_device_object, "public_key");
    json_string = json_string_value(j_value);
    j_value = json_object_get(j_device_object, "secret_key");
    json_string = json_string_value(j_value);

    ret = 0;
exit:
    if (ret)
    {
    }
    return ret;
}

int database_populate_new_entry(json_t *j_device_object, database_entry_t *device_entry, void *context)
{
    uuid_t b_uuid;
    char *uuid = NULL;
    int return_code;

    if (j_device_object == NULL || device_entry == NULL)
    {
        return -1;
    }

    uuid_generate_random(b_uuid);

    uuid = malloc(37);
    if (uuid == NULL)
    {
        return -1;
    }

    uuid_unparse(b_uuid, uuid);

    if (json_object_set_new(
            j_device_object, "uuid", json_stringn(uuid, 37)) != 0)
    {
        return_code = -1;
        goto exit;
    }

    if (device_new_credentials(j_device_object, context))
    {
        return_code = -1;
        goto exit;
    }

    return_code = database_populate_entry(j_device_object, device_entry);

exit:
    free(uuid);
    json_decref(j_device_object);
    return return_code;
}

int database_prepare_array(json_t *j_array, linked_list_t *device_list)
{
    linked_list_entry_t *list_entry;
    database_entry_t *device_entry;
    json_t *j_entry;
    char psk_string[256];
    char psk_id_string[256];
    size_t psk_string_len;
    size_t psk_id_string_len;

    if (device_list == NULL || !json_is_array(j_array))
    {
        return -1;
    }

    for (list_entry = device_list->head; list_entry != NULL; list_entry = list_entry->next)
    {
        psk_string_len = sizeof(psk_string);
        psk_id_string_len = sizeof(psk_id_string);

        device_entry = (database_entry_t *)list_entry->data;

        base64_encode(device_entry->psk, device_entry->psk_len, psk_string, &psk_string_len);
        base64_encode(device_entry->psk_id, device_entry->psk_id_len, psk_id_string, &psk_id_string_len);

        j_entry = json_pack("{s:s, s:s, s:s}", "uuid", device_entry->uuid, "psk", psk_string, "psk_id",
                            psk_id_string);
        if (j_entry == NULL)
        {
            return -1;
        }

        if (json_array_append_new(j_array, j_entry))
        {
            return -1;
        }
    }

    return 0;
}
