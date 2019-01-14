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

#include <mbedtls/ssl.h>

int psk_callback(void *p_cont, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len)
{
    coap_settings_t *coap = (coap_settings_t *)p_cont;
    device_database_t *curr = (device_database_t *)(coap->security);

    while (curr != NULL)
    {
        if (memcmp(name, curr->psk_id, name_len) == 0)
        {
            return mbedtls_ssl_set_hs_psk(ssl, curr->psk, curr->psk_len);
        }
        curr = curr->next;
    }

    return -1;
}


uint8_t lwm2m_buffer_send(void * sessionH, uint8_t * buffer, size_t length, void * userdata)
{
    return COAP_NO_ERROR;
}

