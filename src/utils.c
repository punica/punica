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

#include "utils.h"
#include "punica.h"

#include <assert.h>

static const char *base64_table =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char *utils_base64_encode(const uint8_t *data, size_t length)
{
    size_t buffer_length = ((length + 2) / 3) * 4 + 1; // +1 for null-terminator
    char *buffer;
    static uint8_t previous_byte;
    int data_index = 0,
        buffer_index = 0;

    buffer = malloc(buffer_length);
    if (buffer == NULL)
    {
        return NULL;
    }

    for (data_index = 0; data_index < length; data_index++)
    {
        switch (data_index % 3)
        {
        case 2:
            buffer[buffer_index++] = base64_table[
                                         ((previous_byte & 0x0f) << 2) + ((data[data_index] & 0xc0) >> 6)
                                     ];
            buffer[buffer_index++] = base64_table[data[data_index] & 0x3f];
            break;
        case 1:
            buffer[buffer_index++] = base64_table[
                                         ((previous_byte & 0x03) << 4) + ((data[data_index] & 0xf0) >> 4)
                                     ];
            break;
        case 0:
            buffer[buffer_index++] = base64_table[(data[data_index] & 0xfc) >> 2];
            break;
        }
        previous_byte = data[data_index];
    }

    if ((data_index % 3) == 2)
    {
        buffer[buffer_index++] = base64_table[(previous_byte & 0x0f) << 2];
        buffer[buffer_index++] = '=';
    }
    else if ((data_index % 3) == 1)
    {
        buffer[buffer_index++] = base64_table[(previous_byte & 0x03) << 4];
        buffer[buffer_index++] = '=';
        buffer[buffer_index++] = '=';
    }

    buffer[buffer_index++] = '\0';

    assert(buffer_index == buffer_length);

    return buffer;
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
