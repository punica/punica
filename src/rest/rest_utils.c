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

#include "rest_utils.h"

#include "../punica.h"

#define PSK_ID_BUFFER_LENGTH      12
#define PSK_BUFFER_LENGTH         16

static int find_existing_serial(uint8_t *serial, size_t length, linked_list_t *list)
{
    linked_list_entry_t *device_entry;
    database_entry_t *device_data;

    for (device_entry = list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (device_data)
        {
            if (device_data->serial_len == length)
            {
                if (memcmp(device_data->serial, serial, length) == 0)
                {
                    return -1;
                }
            }
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
    uint8_t binary_buffer[PSK_ID_BUFFER_LENGTH / 2];
    const char hex_table[16] = {"0123456789ABCDEF"};
    uint8_t nibble;

    device_entry->public_key = malloc(PSK_ID_BUFFER_LENGTH);
    device_entry->secret_key = malloc(PSK_BUFFER_LENGTH);

    if (device_entry->public_key == NULL
        || device_entry->secret_key == NULL)
    {
        return -1;
    }

    ret = rest_get_random(binary_buffer, sizeof(binary_buffer));
    if (ret <= 0)
    {
        return -1;
    }

    // PSK ID is a string of random hexadecimal characters
    for (int i = 0; i < sizeof(binary_buffer); i++)
    {
        nibble = (binary_buffer[i] >> 4) & 0x0F;
        device_entry->public_key[i * 2] = hex_table[nibble];

        nibble = (binary_buffer[i]) & 0x0F;
        device_entry->public_key[(i * 2) + 1] = hex_table[nibble];
    }
    device_entry->public_key_len = PSK_ID_BUFFER_LENGTH;

    ret = rest_get_random(device_entry->secret_key, PSK_BUFFER_LENGTH);
    if (ret <= 0)
    {
        return -1;
    }
    device_entry->secret_key_len = PSK_BUFFER_LENGTH;

    return 0;
}

static int device_new_certificate(database_entry_t *device_entry, linked_list_t *device_list, const char *certificate, const char *private_key)
{
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

    if (gnutls_load_file(certificate, &ca_cert_buffer)
        || gnutls_load_file(private_key, &ca_key_buffer))
    {
        goto exit;
    }

    if (gnutls_x509_crt_import(ca_cert, &ca_cert_buffer, GNUTLS_X509_FMT_PEM)
        || gnutls_x509_privkey_import(ca_key, &ca_key_buffer, GNUTLS_X509_FMT_PEM))
    {
        goto exit;
    }

    if (gnutls_x509_privkey_generate(device_key, GNUTLS_PK_EC, GNUTLS_CURVE_TO_BITS(GNUTLS_ECC_CURVE_SECP256R1), 0))
    {
        goto exit;
    }

    device_entry->serial = malloc(20);
    if (device_entry->serial == NULL)
    {
        goto exit;
    }

    do
    {
        generate_serial(device_entry->serial, &device_entry->serial_len);
    } while (find_existing_serial(device_entry->serial, device_entry->serial_len, device_list));

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

int device_new_credentials(database_entry_t *device_entry, linked_list_t *device_list, const char *certificate, const char *private_key)
{
    if (device_entry->mode == DEVICE_CREDENTIALS_PSK)
    {
        return device_new_psk(device_entry);
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_CERT)
    {
        return device_new_certificate(device_entry, device_list, certificate, private_key);
    }
    else if (device_entry->mode == DEVICE_CREDENTIALS_NONE)
    {
        return 0;
    }
    else
    {
        return -1;
    }
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

int utils_load_certificate(uint8_t *buffer, size_t *length, const char *cert_file)
{
    static bool cert_loaded = false;
    static gnutls_datum_t cert_buffer = {NULL, 0};

    if (cert_loaded == false)
    {
        if (gnutls_load_file(cert_file, &cert_buffer) != 0)
        {
            return -1;
        }
        cert_loaded = true;
    }

    if (*length < cert_buffer.size)
    {
        return -1;
    }

    memcpy(buffer, cert_buffer.data, cert_buffer.size);
    *length = cert_buffer.size;

    return 0;
}

json_t *json_object_from_string(const char *string, const char *key)
{
    json_t *j_object, *j_string;

    j_object = json_object();
    if (j_object == NULL)
    {
        return NULL;
    }

    j_string = json_string(string);
    if (j_string == NULL)
    {
        return NULL;
    }

    if (json_object_set_new(j_object, key, j_string) != 0)
    {
        json_decref(j_string);
        return NULL;
    }

    return j_object;
}

json_t *json_object_from_binary(uint8_t *buffer, const char *key, size_t buffer_length)
{
    char base64_string[1024] = {0};
    size_t base64_length = sizeof(base64_string);
    json_t *j_object;

    if (base64_encode(buffer, buffer_length, base64_string, &base64_length) != 0)
    {
        return NULL;
    }

    j_object = json_object_from_string(base64_string, key);
    if (j_object == NULL)
    {
        return NULL;
    }

    return j_object;
}

char *string_from_json_object(json_t *j_object, const char *key)
{
    json_t *j_value;
    const char *string;

    j_value = json_object_get(j_object, key);
    if (j_value == NULL)
    {
        return NULL;
    }

    string = json_string_value(j_value);
    if (string == NULL)
    {
        return NULL;
    }

    return strdup(string);
}

uint8_t *binary_from_json_object(json_t *j_object, const char *key, size_t *buffer_length)
{
    uint8_t *binary_buffer;
    int status;
    char *base64_string;

    base64_string = string_from_json_object(j_object, key);
    if (base64_string == NULL)
    {
        return NULL;
    }

    if (base64_decode(base64_string, NULL, buffer_length) != 0)
    {
        free(base64_string);
        return NULL;
    }

    binary_buffer = malloc(*buffer_length);
    if (binary_buffer == NULL)
    {
        free(base64_string);
        return NULL;
    }

    status = base64_decode(base64_string, binary_buffer, buffer_length);
    free(base64_string);

    if (status != 0)
    {
        free(binary_buffer);
        return NULL;
    }

    return binary_buffer;
}
