/*
 * Punica - LwM2M server with REST API
 * Copyright (C) 2019 8devices
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

#include "connection-secure.h"
#include "restserver.h"

int psk_callback(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
    database_entry_t *device_data;
    rest_list_entry_t *device_entry;
    rest_list_t *device_list;

    device_list = gnutls_session_get_ptr(session);
    if (device_list == NULL)
    {
        return -1;
    }

    for (device_entry = device_list->head; device_entry != NULL; device_entry = device_entry->next)
    {
        device_data = (database_entry_t *)device_entry->data;

        if (memcmp(username, device_data->psk_id, device_data->psk_id_len) == 0)
        {
            key->data = gnutls_malloc(device_data->psk_len);
            if (key->data == NULL)
            {
                return -1;
            }
            key->size = device_data->psk_len;
            memcpy(key->data, device_data->psk, device_data->psk_len);
            return 0;
        }
    }

    return -1;
}

uint8_t lwm2m_buffer_send(void *session, uint8_t *buffer, size_t length, void *user_data)
{
    connection_api_t *conn_api = (connection_api_t *)user_data;

    if (session == NULL)
    {
        log_message(LOG_LEVEL_ERROR, "Failed sending %lu bytes, missing connection\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    if (conn_api->f_send(conn_api, session, buffer, length) < 0)
    {
        log_message(LOG_LEVEL_ERROR, "Failed sending %lu bytes\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void *session1, void *session2, void *userData)
{
    return (session1 == session2);
}

int lwm2m_client_validate(char *name, void *session, void *user_data)
{
    connection_api_t *api = (connection_api_t *)user_data;

    if (api->f_validate == NULL)
    {
        return 0;
    }

    return api->f_validate(name, session);
}
