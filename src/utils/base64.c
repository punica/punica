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

#include <nettle/base64.h>
#include <string.h>

#include <stdio.h>

#include "base64.h"

size_t base64_encoded_length(size_t data_length)
{
    return BASE64_ENCODE_RAW_LENGTH(data_length) + 1;
}

size_t base64_decoded_length(size_t b64_string_length)
{
    return BASE64_DECODE_LENGTH(b64_string_length - 1);
}

int base64_encode(const uint8_t *data, size_t length,
                  char *base64_string, size_t *base64_length)
{
    struct base64_encode_ctx b64_ctx;

    if ((base64_string == NULL)
        || (base64_length == NULL))
    {
        printf("NU TIKRAI ZOPAA!!! (nes nu tipo %p %p %p)\n",
               data, base64_string, base64_length);
        return -1;
    }

    base64_encode_init(&b64_ctx);
    *base64_length = base64_encode_update(&b64_ctx, base64_string,
                                          length, data);
    *base64_length += base64_encode_final(&b64_ctx,
                                          base64_string + *base64_length);
    base64_string[*base64_length++] = '\0';

    return 0;
}

int base64_decode(const char *base64_string, uint8_t *data, size_t *length)
{
    struct base64_decode_ctx b64_ctx;

    base64_decode_init(&b64_ctx);

    if (base64_decode_update(&b64_ctx, length, data,
                             strlen(base64_string) + 1, base64_string) != 0)
    {
        return -1;
    }

    if (base64_decode_final(&b64_ctx) != 0)
    {
        return -1;
    }

    return 0;
}
