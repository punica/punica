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

#define DATABASE_UUID_KEY_BIT       0x01
#define DATABASE_MODE_KEY_BIT       0x02
#define DATABASE_NAME_KEY_BIT       0x04
#define DATABASE_PUBLIC_KEY_BIT     0x08
#define DATABASE_SECRET_KEY_BIT     0x10
#define DATABASE_SERIAL_KEY_BIT     0x20
#define DATABASE_ALL_NEW_KEYS_SET   0x06
#define DATABASE_ALL_KEYS_SET       0x3F

json_t *database_entry_to_json(void *entry, const char *key, database_base64_action action, size_t entry_size)
{
    json_t *j_object = NULL, *j_string = NULL;
    char base64_string[1024];
    size_t base64_length = sizeof(base64_string);
    int status = -1;

    j_object = json_object();
    if (j_object == NULL)
    {
        goto exit;
    }

    if (action == BASE64_DECODE_FALSE)
    {
        j_string = json_string((const char *)entry);
        if (j_string == NULL)
        {
            goto exit;
        }

        if (json_object_set_new(j_object, key, j_string))
        {
            json_decref(j_string);
            goto exit;
        }
    }
    else if (action == BASE64_ENCODE_TRUE)
    {
        if (base64_encode(entry, entry_size, base64_string, &base64_length))
        {
            goto exit;
        }

        j_string = json_string((const char *)base64_string);
        if (j_string == NULL)
        {
            goto exit;
        }

        if (json_object_set_new(j_object, key, j_string))
        {
            json_decref(j_string);
            goto exit;
        }
    }
    else
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        json_decref(j_object);
        return NULL;
    }
    return j_object;
}

void *database_json_to_entry(json_t *j_object, const char *key, database_base64_action base64_action, size_t *entry_size)
{
    json_t *j_value;
    const char *json_string;
    size_t binary_length;
    void *entry = NULL;
    int status = -1;

    j_value = json_object_get(j_object, key);
    if (j_value == NULL)
    {
        goto exit;
    }

    json_string = json_string_value(j_value);
    if (json_string == NULL)
    {
        goto exit;
    }

    if (base64_action == BASE64_DECODE_FALSE)
    {
        entry = strdup(json_string);
        if (entry == NULL)
        {
            goto exit;
        }
        if (entry_size)
        {
            *entry_size = strlen(entry) + 1;
        }
    }
    else if (base64_action == BASE64_DECODE_TRUE)
    {
        if (base64_decode(json_string, NULL, &binary_length))
        {
            goto exit;
        }

        entry = malloc(binary_length);
        if (entry == NULL)
        {
            goto exit;
        }

        if (base64_decode(json_string, entry, &binary_length))
        {
            goto exit;
        }

        *entry_size = binary_length;
    }
    else
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        free(entry);
        return NULL;
    }
    return entry;
}

static int database_find_existing_entry(const char *name, linked_list_t *device_list)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (strcmp(name, device_data->name) == 0)
        {
            return -1;
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

static int device_new_psk(database_entry_t *device_entry)
{
    size_t ret = 0;
    size_t name_len = strlen(device_entry->name);

    // PSK ID maximum length 128 according to specification
    if (name_len > 127)
    {
        goto exit;
    }

    device_entry->public_key = malloc(name_len + 1);
    if (device_entry->public_key == NULL)
    {
        goto exit;
    }
    memcpy(device_entry->public_key, device_entry->name, name_len + 1);
    device_entry->public_key_len = name_len + 1;

    device_entry->secret_key = malloc(16);
    if (device_entry->secret_key == NULL)
    {
        goto exit;
    }
    ret = rest_get_random(device_entry->secret_key, 16);
    device_entry->secret_key_len = ret;

exit:
    if (ret <= 0)
    {
        return -1;
    }
    return 0;
}

static int device_new_certificate(database_entry_t *device_entry, void *context)
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

    device_entry->serial = malloc(20);
    if (device_entry->serial == NULL)
    {
        goto exit;
    }

    //TODO: check for existing serial
    generate_serial(device_entry->serial, &device_entry->serial_len);
    activation_time = time(NULL);

    if (gnutls_x509_crt_set_version(device_cert, 3)
        || gnutls_x509_crt_set_serial(device_cert, device_entry->serial, device_entry->serial_len)
        || gnutls_x509_crt_set_activation_time(device_cert, activation_time)
        || gnutls_x509_crt_set_expiration_time(device_cert, activation_time + 60 * 60)
        || gnutls_x509_crt_set_key(device_cert, device_key))
    {
        goto exit;
    }

    if (gnutls_x509_crt_set_subject_alt_name(device_cert, GNUTLS_SAN_DNSNAME, device_entry->uuid, strlen(device_entry->uuid) + 1, GNUTLS_FSAN_SET))
    {
        goto exit;
    }

    if (gnutls_x509_crt_sign(device_cert, ca_cert, ca_key))
    {
        goto exit;
    }

    gnutls_x509_crt_export(device_cert, GNUTLS_X509_FMT_PEM, NULL, &device_entry->public_key_len);
    gnutls_x509_privkey_export(device_key, GNUTLS_X509_FMT_PEM, NULL, &device_entry->secret_key_len);

    device_entry->public_key = malloc(device_entry->public_key_len);
    device_entry->secret_key = malloc(device_entry->secret_key_len);

    if (device_entry->public_key == NULL
        || device_entry->secret_key == NULL)
    {
        goto exit;
    }

    if (gnutls_x509_crt_export(device_cert, GNUTLS_X509_FMT_PEM, device_entry->public_key, &device_entry->public_key_len)
        || gnutls_x509_privkey_export(device_key, GNUTLS_X509_FMT_PEM, device_entry->secret_key, &device_entry->secret_key_len))
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

static int device_new_credentials(database_entry_t *device_entry, void *context)
{
    if (device_entry->mode == MODE_PSK)
    {
        if (device_new_psk(device_entry))
        {
            return -1;
        }
    }
    else if (device_entry->mode == MODE_CERT)
    {
        if (device_new_certificate(device_entry, context))
        {
            return -1;
        }
    }
    else
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
        free(device_entry->uuid);
        free(device_entry->name);
        free(device_entry->public_key);
        free(device_entry->secret_key);

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

int database_validate_entry(json_t *j_device_object, linked_list_t *device_list)
{
    int key_check = 0;
    const char *key, *value_string;
    json_t *j_value;
    uint8_t buffer[512];
    size_t buffer_len = sizeof(buffer);
    int ret;

    if (!json_is_object(j_device_object))
    {
        return -1;
    }

    json_object_foreach(j_device_object, key, j_value)
    {
        if (!json_is_string(j_value))
        {
            return -1;
        }
        if (strcasecmp(key, "uuid") == 0)
        {
            key_check |= DATABASE_UUID_KEY_BIT;
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
        else if (strcasecmp(key, "mode") == 0)
        {
            value_string = json_string_value(j_value);

            if (strcasecmp(value_string, "psk")
                && strcasecmp(value_string, "cert"))
            {
                return -1;
            }

            key_check |= DATABASE_MODE_KEY_BIT;
        }
        else if (strcasecmp(key, "public_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if (ret != BASE64_ERR_NONE)
            {
                return -1;
            }
            key_check |= DATABASE_PUBLIC_KEY_BIT;
        }
        else if (strcasecmp(key, "secret_key") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if ((ret != BASE64_ERR_NONE) && (ret != BASE64_ERR_ARG)) // key might contain string with length of zero
            {
                return -1;
            }
            key_check |= DATABASE_SECRET_KEY_BIT;
        }
        else if (strcasecmp(key, "serial") == 0)
        {
            ret = base64_decode(json_string_value(j_value), buffer, &buffer_len);
            if ((ret != BASE64_ERR_NONE) && (ret != BASE64_ERR_ARG))
            {
                return -1;
            }
            key_check |= DATABASE_SERIAL_KEY_BIT;
        }
    }

//  function does not check for duplicate keys
    if (key_check != DATABASE_ALL_KEYS_SET)
    {
        return -1;
    }

    return 0;
}

database_entry_t *database_build_entry(json_t *j_device_object)
{
    json_t *j_value;
    const char *mode;
    int status = -1;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        goto exit;
    }

    mode = database_json_to_entry(j_device_object, "mode", BASE64_DECODE_FALSE, NULL);
    if (mode == NULL)
    {
        goto exit;
    }

    if (strcasecmp(mode, "psk") == 0)
    {
        device_entry->mode = MODE_PSK;
        device_entry->secret_key = database_json_to_entry(j_device_object, "secret_key", BASE64_DECODE_TRUE, &device_entry->secret_key_len);
    }
    else if (strcasecmp(mode, "cert") == 0)
    {
        device_entry->mode = MODE_CERT;
        device_entry->serial = database_json_to_entry(j_device_object, "serial", BASE64_DECODE_TRUE, &device_entry->serial_len);
    }
    else
    {
        goto exit;
    }

    device_entry->uuid = database_json_to_entry(j_device_object, "uuid", BASE64_DECODE_FALSE, NULL);
    device_entry->name = database_json_to_entry(j_device_object, "name", BASE64_DECODE_FALSE, NULL);
    device_entry->public_key = database_json_to_entry(j_device_object, "public_key", BASE64_DECODE_TRUE, &device_entry->public_key_len);
    if (device_entry->uuid == NULL
        || device_entry->name == NULL
        || device_entry->public_key == NULL
        || (device_entry->secret_key == NULL
        && device_entry->serial == NULL))
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    return device_entry;
}

database_entry_t *database_build_new_entry(json_t *j_device_object, void *context)
{
    uuid_t b_uuid;
    char *uuid = NULL;
    const char *mode;
    int status = -1;
    json_t *j_value;
    database_entry_t *device_entry = NULL;

    if (j_device_object == NULL)
    {
        goto exit;
    }

    device_entry = calloc(1, sizeof(database_entry_t));
    if (device_entry == NULL)
    {
        goto exit;
    }

    mode = database_json_to_entry(j_device_object, "mode", BASE64_DECODE_FALSE, NULL);
    if (mode == NULL)
    {
        goto exit;
    }

    if (strcasecmp(mode, "psk") == 0)
    {
        device_entry->mode = MODE_PSK;
    }
    else if (strcasecmp(mode, "cert") == 0)
    {
        device_entry->mode = MODE_CERT;
    }
    else
    {
        goto exit;
    }

    device_entry->name = database_json_to_entry(j_device_object, "name", BASE64_DECODE_FALSE, NULL);
    if (device_entry->name == NULL)
    {
        goto exit;
    }

    uuid_generate_random(b_uuid);

    uuid = malloc(37);
    if (uuid == NULL)
    {
        goto exit;
    }

    uuid_unparse(b_uuid, uuid);

    device_entry->uuid = strdup(uuid);
    if (device_entry->uuid == NULL)
    {
        goto exit;
    }

    if (device_new_credentials(device_entry, context))
    {
        goto exit;
    }

    status = 0;
exit:
    if (status)
    {
        database_free_entry(device_entry);
        device_entry = NULL;
    }
    free(uuid);
    free(mode);
    return device_entry;
}

int database_prepare_array(json_t *j_array, linked_list_t *device_list)
{
    linked_list_entry_t *list_entry;
    database_entry_t *device_entry;
    json_t *j_entry;
    char base64_secret_key[1024];
    char base64_public_key[1024];
    char base64_serial[64];
    size_t base64_length;
    const char *mode_string;

    if (device_list == NULL || !json_is_array(j_array))
    {
        return -1;
    }

    for (list_entry = device_list->head; list_entry != NULL; list_entry = list_entry->next)
    {
        device_entry = (database_entry_t *)list_entry->data;

        memset(base64_secret_key, 0, sizeof(base64_secret_key));
        memset(base64_public_key, 0, sizeof(base64_public_key));
        memset(base64_serial, 0, sizeof(base64_serial));

        base64_length = sizeof(base64_secret_key);
        if (base64_encode(device_entry->secret_key, device_entry->secret_key_len, base64_secret_key, &base64_length))
        {
            return -1;
        }

        base64_length = sizeof(base64_public_key);
        if (base64_encode(device_entry->public_key, device_entry->public_key_len, base64_public_key, &base64_length))
        {
            return -1;
        }

        base64_length = sizeof(base64_serial);
        if (base64_encode(device_entry->serial, device_entry->serial_len, base64_serial, &base64_length))
        {
            return -1;
        }

        if (device_entry->mode == MODE_PSK)
        {
            mode_string = "psk";
        }
        else if (device_entry->mode == MODE_CERT)
        {
            mode_string = "cert";
        }
        else
        {
            return -1;
        }

        j_entry = json_pack("{s:s, s:s, s:s, s:s, s:s, s:s}", "uuid", device_entry->uuid, "name", device_entry->name, "mode", mode_string, "secret_key", base64_secret_key, "public_key", base64_public_key, "serial", base64_serial);
        if (j_entry == NULL)
        {
            return -1;
        }

        if (json_array_append_new(j_array, j_entry))
        {
            json_decref(j_entry);
            return -1;
        }
    }

    return 0;
}

int utils_get_server_key(uint8_t *buffer, size_t *length, void *context)
{
    rest_context_t *rest = (rest_context_t *)context;
    gnutls_x509_crt_t cert = NULL;
    gnutls_datum_t cert_buffer = {NULL, 0};
    int ret = -1;

    gnutls_x509_crt_init(&cert);

    if (gnutls_load_file(rest->settings->coap.certificate_file, &cert_buffer))
    {
        goto exit;
    }
    if (gnutls_x509_crt_import(cert, &cert_buffer, GNUTLS_X509_FMT_PEM))
    {
        goto exit;
    }
    if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, buffer, length))
    {
        goto exit;
    }

    ret = 0;
exit:
    gnutls_free(cert_buffer.data);
    gnutls_x509_crt_deinit(cert);
    return ret;
}
