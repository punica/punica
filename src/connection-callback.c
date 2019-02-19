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

static void *psk_list;

void set_psk_callback_data(void *data)
{
    psk_list = data;
}

int psk_callback(gnutls_session_t session, const char *username, gnutls_datum_t *key)
{
    rest_list_t *device_list = psk_list;
    database_entry_t *device_data;
    rest_list_entry_t *device_entry;

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

int lwm2m_client_validate(char *name, void *session)
{
    device_connection_t *conn = (device_connection_t *)session;
    gnutls_x509_crt_t cert;
    const gnutls_datum_t *cert_list;
    char common_name[256];
    size_t size;
    gnutls_cipher_algorithm_t cipher;
    gnutls_kx_algorithm_t key_ex;

    cipher = gnutls_cipher_get(conn->session);
    key_ex = gnutls_kx_get(conn->session);

    if (!(key_ex == GNUTLS_KX_ECDHE_ECDSA && (cipher == GNUTLS_CIPHER_AES_128_CCM_8 ||
                                              cipher == GNUTLS_CIPHER_AES_128_CBC)))
    {
        return 0;
    }

    cert_list = gnutls_certificate_get_peers(conn->session, NULL);
    if (cert_list == NULL)
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER))
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    size = sizeof(common_name);
    if (gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, common_name, &size))
    {
        return COAP_500_INTERNAL_SERVER_ERROR;
    }

    if (strcmp(name, common_name) == 0)
    {
        return 0;
    }

    return COAP_400_BAD_REQUEST;
}
