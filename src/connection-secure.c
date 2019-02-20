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

#define BUFFER_SIZE 1024

typedef struct secure_connection_context_t
{
    connection_api_t api;
    device_connection_t *connection_list;
    int port;
    int address_family;
    const char *certificate_file;
    const char *private_key_file;
    int listen_socket;
    gnutls_certificate_credentials_t server_cert;
    gnutls_priority_t priority_cache;
    gnutls_datum_t cookie_key;
    gnutls_psk_server_credentials_t server_psk;
    void *data;
    f_psk_cb_t psk_cb;
} secure_connection_context_t;

static ssize_t prv_net_send(gnutls_transport_ptr_t context, const void *data, size_t size)
{
    device_connection_t *conn = (device_connection_t *)context;

    return sendto(conn->sock, data, size, 0, (struct sockaddr *)&conn->addr, conn->addr_size);
}

static int prv_new_socket(void *this)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int sock, enable;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[16];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = context->address_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_flags |= AI_PASSIVE;

    sprintf(port_str, "%d", context->port);
    if (getaddrinfo(NULL, port_str, &hints, &addr_list) != 0)
    {
        return -1;
    }

    for (cur = addr_list; cur != NULL; cur = cur->ai_next)
    {
        sock = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (sock < 0)
        {
            continue;
        }

        enable = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&enable, sizeof(enable)))
        {
            close(sock);
            sock = -1;
            continue;
        }

        if (bind(sock, cur->ai_addr, cur->ai_addrlen))
        {
            close(sock);
            sock = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(addr_list);
    return sock;
}

static int prv_switch_sockets(void *this, device_connection_t *connection)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;

    if (connect(context->listen_socket, (struct sockaddr *)&connection->addr,
                sizeof(struct sockaddr_storage)))
    {
        return -1;
    }

    connection->sock = context->listen_socket;
    context->listen_socket = prv_new_socket(this);

    return 0;
}

static int prv_cookie_negotiate(void *this, device_connection_t *connection,
                                gnutls_dtls_prestate_st *prestate)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int ret;
    char buffer[BUFFER_SIZE];

    for (int i = 0; i < 2; i++)
    {
        connection->addr_size = sizeof(connection->addr);

        ret = recvfrom(connection->sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&connection->addr,
                       &connection->addr_size);
        if (ret > 0)
        {
            memset(prestate, 0, sizeof(gnutls_dtls_prestate_st));

            ret = gnutls_dtls_cookie_verify(&context->cookie_key, &connection->addr, sizeof(connection->addr),
                                            buffer,
                                            ret, prestate);
            if (ret == 0)
            {
                return 0;
            }
            else
            {
                gnutls_dtls_cookie_send(&context->cookie_key, &connection->addr, sizeof(connection->addr), prestate,
                                        connection, prv_net_send);
            }
        }
        else
        {
            return -1;
        }
    }

    return -1;
}

static int prv_connection_init(void *this, device_connection_t *connection,
                               gnutls_dtls_prestate_st *prestate)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int ret = -1;

    if (gnutls_init(&connection->session, GNUTLS_SERVER | GNUTLS_DATAGRAM))
    {
        goto exit;
    }
    if (gnutls_credentials_set(connection->session, GNUTLS_CRD_PSK, context->server_psk))
    {
        goto exit;
    }
    if (gnutls_credentials_set(connection->session, GNUTLS_CRD_CERTIFICATE, context->server_cert))
    {
        goto exit;
    }
    if (gnutls_priority_set(connection->session, context->priority_cache))
    {
        goto exit;
    }

    gnutls_certificate_server_set_request(connection->session, GNUTLS_CERT_REQUIRE);
    gnutls_dtls_prestate_set(connection->session, prestate);
    gnutls_transport_set_ptr(connection->session, (void *)((intptr_t)connection->sock));
    gnutls_session_set_ptr(connection->session, context);

    ret = 0;
exit:
    if (ret)
    {
        gnutls_deinit(connection->session);
    }
    return ret;
}

static device_connection_t *prv_connection_new_incoming(void *this)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int ret;
    const char *err_str;
    gnutls_dtls_prestate_st prestate;
    device_connection_t *conn;

    conn = (device_connection_t *)malloc(sizeof(device_connection_t));
    if (conn == NULL)
    {
        return NULL;
    }
    conn->sock = context->listen_socket;

    if (prv_cookie_negotiate(this, conn, &prestate) == 0)
    {
//      the current socket will be taken over by the client connection and a new one created for listening for incoming connections
        if (prv_switch_sockets(this, conn))
        {
            context->listen_socket = prv_new_socket(this);

            close(conn->sock);
            free(conn);
            return NULL;
        }

        if (prv_connection_init(this, conn, &prestate))
        {
            close(conn->sock);
            free(conn);
            return NULL;
        }

        do
        {
            ret = gnutls_handshake(conn->session);
        } while (ret == GNUTLS_E_AGAIN);

        if (ret < 0)
        {
            err_str = gnutls_strerror(ret);
            log_message(LOG_LEVEL_WARN, "Handshake failed with message: '%s'\n", err_str);

            gnutls_deinit(conn->session);
            close(conn->sock);
            free(conn);
            return NULL;
        }
    }
    else
    {
        free(conn);
        return NULL;
    }

    return conn;
}

static int prv_psk_callback(gnutls_session_t session, const char *name, gnutls_datum_t *key)
{
    secure_connection_context_t *context;
    uint8_t *psk_buff;
    size_t psk_len;

    context = gnutls_session_get_ptr(session);

    if (context->psk_cb(name, context->data, &psk_buff, &psk_len))
    {
        return -1;
    }

    key->data = malloc(psk_len);
    if (key->data == NULL)
    {
        return -1;
    }

    key->size = psk_len;
    memcpy(key->data, psk_buff, psk_len);

    return 0;
}

int dtls_connection_api_init(connection_api_t **conn_api, int port, int address_family,
                             const char *certificate_file, const char *private_key_file, void *data, f_psk_cb_t psk_cb)
{
    secure_connection_context_t *context;
    context = calloc(1, sizeof(secure_connection_context_t));
    if (context == NULL)
    {
        return -1;
    }

    context->port = port;
    context->address_family = address_family;
    context->certificate_file = certificate_file;
    context->private_key_file = private_key_file;
    context->data = data;
    context->psk_cb = psk_cb;

    context->api.f_start = connection_start_secure;
    context->api.f_receive = connection_receive_secure;
    context->api.f_send = connection_send_secure;
    context->api.f_close = connection_close_secure;
    context->api.f_stop = connection_stop_secure;
    context->api.f_validate = connection_validate_secure;
    *conn_api = &context->api;

    return 0;
}

int connection_start_secure(void *this)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int ret = -1;

    if (gnutls_global_init())
    {
        goto exit;
    }

    if (context->certificate_file)
    {
        if (gnutls_certificate_allocate_credentials(&context->server_cert) != GNUTLS_E_SUCCESS)
        {
            goto exit;
        }
        if (gnutls_certificate_set_x509_trust_file(context->server_cert, context->certificate_file,
                                                   GNUTLS_X509_FMT_PEM) == 0)
        {
            goto exit;
        }
        if (gnutls_certificate_set_x509_key_file(context->server_cert, context->certificate_file,
                                                 context->private_key_file, GNUTLS_X509_FMT_PEM))
        {
            goto exit;
        }
    }

    if (gnutls_priority_init(&context->priority_cache,
                             "NORMAL:+VERS-DTLS1.2:+AES-128-CCM-8:+PSK:+ECDHE-ECDSA",
                             NULL) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }
    if (gnutls_key_generate(&context->cookie_key, GNUTLS_COOKIE_KEY_SIZE) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }
    if (gnutls_psk_allocate_server_credentials(&context->server_psk) != GNUTLS_E_SUCCESS)
    {
        goto exit;
    }

    gnutls_psk_set_server_credentials_function(context->server_psk, prv_psk_callback);

    context->listen_socket = prv_new_socket(this);
    ret = context->listen_socket;

exit:
    if (ret <= 0)
    {
        gnutls_certificate_free_credentials(context->server_cert);
        gnutls_priority_deinit(context->priority_cache);
        gnutls_psk_free_server_credentials(context->server_psk);
    }
    return ret;
}

int connection_receive_secure(void *this, uint8_t *buffer, size_t size, void **connection,
                              struct timeval *tv)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    int ret, nfds = 0;
    fd_set read_fds;
    device_connection_t *conn_curr = context->connection_list;

    FD_ZERO(&read_fds);

//  set active file descriptors and calculate required nfds
    while (conn_curr != NULL)
    {
        FD_SET(conn_curr->sock, &read_fds);
        if (conn_curr->sock >= nfds)
        {
            nfds = conn_curr->sock + 1;
        }
        conn_curr = conn_curr->next;
    }

    FD_SET(context->listen_socket, &read_fds);
    if (context->listen_socket >= nfds)
    {
        nfds = context->listen_socket + 1;
    }

    ret = select(nfds, &read_fds, NULL, NULL, tv);
    if (ret <= 0)
    {
        return ret;
    }

    conn_curr = context->connection_list;
    while (conn_curr != NULL)
    {
        if (FD_ISSET(conn_curr->sock, &read_fds))
        {
            *connection = conn_curr;
            conn_curr->addr_size = sizeof(conn_curr->addr);
            ret = recvfrom(conn_curr->sock, buffer, size, MSG_PEEK,
                           (struct sockaddr *)&conn_curr->addr, &conn_curr->addr_size);
            return gnutls_record_recv(conn_curr->session, buffer, ret);
        }
        conn_curr = conn_curr->next;
    }

    if (FD_ISSET(context->listen_socket, &read_fds))
    {
        device_connection_t *conn_new = prv_connection_new_incoming(this);
        if (conn_new == NULL)
        {
            log_message(LOG_LEVEL_WARN, "Failed to connect to device\n");
            return -1;
        }

        conn_new->next = context->connection_list;
        context->connection_list = conn_new;
    }

    return 0;
}

int connection_close_secure(void *this, void *connection)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    device_connection_t *conn = (device_connection_t *)connection;
    int ret;

    if (context->connection_list == NULL)
    {
        return 0;
    }

    if (conn == context->connection_list)
    {
        context->connection_list = conn->next;
        goto free;
    }

    device_connection_t *conn_curr = context->connection_list;
    do
    {
        if (conn_curr->next == conn)
        {
            conn_curr->next = conn->next;
            goto free;
        }
        conn_curr = conn_curr->next;
    } while (conn_curr->next != NULL);

free:
    do
    {
        ret = gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
    } while (ret == GNUTLS_E_AGAIN);

    if (ret != GNUTLS_E_SUCCESS)
    {
        return -1;
    }

    gnutls_deinit(conn->session);
    close(conn->sock);
    free(conn);
    return 0;
}

int connection_send_secure(void *this, void *connection, uint8_t *buffer, size_t length)
{
    device_connection_t *conn = (device_connection_t *)connection;

    return gnutls_record_send(conn->session, buffer, length);
}

int connection_stop_secure(void *this)
{
    secure_connection_context_t *context = (secure_connection_context_t *)this;
    device_connection_t *curr, *next;

    curr = context->connection_list;
    while (curr != NULL)
    {
        next = curr->next;
        if (connection_close_secure(this, curr))
        {
            log_message(LOG_LEVEL_ERROR, "Failed to deinit session with client\n");
        }
        curr = next;
    }

    gnutls_certificate_free_credentials(context->server_cert);
    gnutls_priority_deinit(context->priority_cache);
    gnutls_psk_free_server_credentials(context->server_psk);
    gnutls_global_deinit();

    close(context->listen_socket);
    free(context);

    return 0;
}

int connection_validate_secure(char *name, void *connection)
{
    device_connection_t *conn = (device_connection_t *)connection;
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
        return -1;
    }
    if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS)
    {
        return -1;
    }
    if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER))
    {
        return -1;
    }

    size = sizeof(common_name);
    if (gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, common_name, &size))
    {
        return -1;
    }

    if (strcmp(name, common_name) == 0)
    {
        return 0;
    }

    return -1;
}
