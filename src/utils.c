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

#include "http_codes.h"
#include "utils.h"
#include "punica.h"

#include <assert.h>

static const char *base64_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int base64_decode(const char *base64_string, uint8_t *data, size_t *length)
{
    if (!base64_string || !length)
    {
        return BASE64_ERR_ARG;
    }

    int string_index, data_index = 0;
    int buffer_length, string_length, padding = 0;
    int i;

    string_length = strlen(base64_string);
    for (i = 0; i < string_length; i++)
    {
        if (base64_string[i] == 0x3d)
        {
            padding++;
            if (base64_string[i + 1] == 0x3d)
            {
                padding++;
            }
            break;
        }
    }

    buffer_length = (string_length / 4) * 3 - padding;
    if (buffer_length <= 0)
    {
        return BASE64_ERR_ARG;
    }

    if (data == NULL)
    {
        *length = buffer_length;
        return BASE64_ERR_NONE;
    }

    if (*length < buffer_length)
    {
        return BASE64_ERR_BUF_SIZE;
    }

    memset(data, 0, *length);

    uint8_t bits6;
    const char *pos;
    for (string_index = 0; string_index < string_length; string_index++)
    {
        if (base64_string[string_index] == 0x3d)
        {
            break;
        }
        if ((pos = strchr(base64_table, base64_string[string_index])) == NULL)
        {
            return BASE64_ERR_INV_CHAR;
        }
        bits6 = pos - base64_table;

        switch (string_index % 4)
        {
        case 0:
            data[data_index] = data[data_index] | (bits6 << 2);
            break;
        case 1:
            data[data_index] = data[data_index] | (bits6 >> 4);
            data[data_index + 1] = data[data_index + 1] | (bits6 << 4);
            break;
        case 2:
            data[data_index + 1] = data[data_index + 1] | (bits6 >> 2);
            data[data_index + 2] = data[data_index + 2] | (bits6 << 6);
            break;
        case 3:
            data[data_index + 2] = data[data_index + 2] | (bits6);
            data_index = data_index + 3;
            break;
        }
    }

    return BASE64_ERR_NONE;
}

int base64_encode(const uint8_t *data, size_t length, char *base64_string, size_t *base64_length)
{
    static uint8_t previous_byte;
    int data_index = 0,
        buffer_index = 0;

    if (data == NULL || length <= 0)
    {
        *base64_length = 0;
        return BASE64_ERR_NONE;
    }

    int string_length = ((length + 2) / 3) * 4;
    if (base64_string == NULL)
    {
        *base64_length = string_length;
        return BASE64_ERR_NONE;
    }

    if (*base64_length < string_length)
    {
        *base64_length = string_length;
        return BASE64_ERR_STR_SIZE;
    }

    for (data_index = 0; data_index < length; data_index++)
    {
        switch (data_index % 3)
        {
        case 2:
            base64_string[buffer_index++] = base64_table[
                                                ((previous_byte & 0x0f) << 2) + ((data[data_index] & 0xc0) >> 6)
                                            ];
            base64_string[buffer_index++] = base64_table[data[data_index] & 0x3f];
            break;
        case 1:
            base64_string[buffer_index++] = base64_table[
                                                ((previous_byte & 0x03) << 4) + ((data[data_index] & 0xf0) >> 4)
                                            ];
            break;
        case 0:
            base64_string[buffer_index++] = base64_table[(data[data_index] & 0xfc) >> 2];
            break;
        }
        previous_byte = data[data_index];
    }

    if ((data_index % 3) == 2)
    {
        base64_string[buffer_index++] = base64_table[(previous_byte & 0x0f) << 2];
        base64_string[buffer_index++] = '=';
    }
    else if ((data_index % 3) == 1)
    {
        base64_string[buffer_index++] = base64_table[(previous_byte & 0x03) << 4];
        base64_string[buffer_index++] = '=';
        base64_string[buffer_index++] = '=';
    }

    base64_string[buffer_index++] = '\0';
    *base64_length = string_length;

    return BASE64_ERR_NONE;
}

int utils_coap_to_http_status(int status)
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

size_t utils_get_random(void *buf, size_t buflen)
{
    FILE *f;
    size_t len;

    f = fopen("/dev/urandom", "r");
    if (f == NULL)
    {
        return 0;
    }

    len = fread(buf, 1, buflen, f);
    fclose(f);
    return len;
}

lwm2m_client_t *utils_find_client(lwm2m_client_t *list, const char *name)
{
    lwm2m_client_t *client;

    if (name == NULL)
    {
        return NULL;
    }

    for (client = list; client != NULL; client = client->next)
    {
        if (strcmp(client->name, name) == 0)
        {
            return client;
        }
    }

    return NULL;
}
