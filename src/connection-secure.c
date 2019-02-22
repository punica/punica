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
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "rest-list.h"

#define BUFFER_SIZE 1024

typedef struct _device_connection_t
{
    int sock;
    gnutls_session_t session;
    struct sockaddr_storage addr;
    socklen_t addr_size;
} device_connection_t;

typedef struct secure_connection_context_t
{
    connection_api_t api;
    rest_list_t *connection_list;
    device_connection_t *connection_listen;
    int port;
    int address_family;
    const char *certificate_file;
    const char *private_key_file;
    gnutls_certificate_credentials_t server_cert;
    gnutls_priority_t priority_cache;
    gnutls_datum_t cookie_key;
    gnutls_psk_server_credentials_t server_psk;
    void *data;
    f_psk_cb_t psk_cb;
} secure_connection_context_t;

static int connection_start_secure(void *context_p);
static int connection_receive_secure(void *context_p, uint8_t *buffer, size_t size,
                                     void **connection, struct timeval *tv);
static int connection_send_secure(void *context_p, void *connection, uint8_t *buffer,
                                  size_t length);
static int connection_close_secure(void *context_p, void *connection);
static int connection_stop_secure(void *context_p);
static int connection_validate_secure(char *name, void *connection);

static ssize_t prv_net_send(gnutls_transport_ptr_t context, const void *data, size_t size)
{
    device_connection_t *conn = (device_connection_t *)context;

    return sendto(conn->sock, data, size, 0, (struct sockaddr *)&conn->addr, conn->addr_size);
}

static int prv_new_socket(secure_connection_context_t *context)
{
    int sock, enable;
    struct addrinfo hints, *addr_list, *cur;
    char port_str[16];
//    struct timeval tv;
//
//    tv.tv_sec = 40;
//    tv.tv_usec = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = context->address_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;

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

//        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
//        {
//            close(sock);
//            sock = -1;
//            continue;
//        }

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

static int prv_connection_init(secure_connection_context_t *context,
                               device_connection_t *connection,
                               gnutls_dtls_prestate_st *prestate)
{
    int ret = -1;

    if (gnutls_init(&connection->session, GNUTLS_SERVER | GNUTLS_DATAGRAM | GNUTLS_NONBLOCK))
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

static device_connection_t *prv_new_connection_listen(secure_connection_context_t *context)
{
    device_connection_t *conn;

    conn = calloc(1, sizeof(device_connection_t));
    if (conn == NULL)
    {
        return NULL;
    }

    conn->sock = prv_new_socket(context);
    if (conn->sock <= 0)
    {
        free(conn);
        return NULL;
    }

    return conn;
}

connection_api_t *dtls_connection_api_init(int port, int address_family,
                                           const char *certificate_file, const char *private_key_file, void *data, f_psk_cb_t psk_cb)
{
    secure_connection_context_t *context;
    context = calloc(1, sizeof(secure_connection_context_t));
    if (context == NULL)
    {
        return NULL;
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

    return &context->api;
}

void dtls_connection_api_deinit(void *context_p)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;

    free(context);
}

static int connection_start_secure(void *context_p)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
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

    context->connection_list = rest_list_new();
    if (context->connection_list == NULL)
    {
        goto exit;
    }

    context->connection_listen = prv_new_connection_listen(context);
    if (context->connection_listen == NULL)
    {
        rest_list_delete(context->connection_list);
        goto exit;
    }

    gnutls_psk_set_server_credentials_function(context->server_psk, prv_psk_callback);

    ret = context->connection_listen->sock;

exit:
    if (ret <= 0)
    {
        gnutls_certificate_free_credentials(context->server_cert);
        gnutls_priority_deinit(context->priority_cache);
        gnutls_psk_free_server_credentials(context->server_psk);
    }
    return ret;
}

static int connection_receive_secure(void *context_p, uint8_t *buffer, size_t size,
                                     void **connection, struct timeval *tv)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    int ret, sock, nfds = 0;
    fd_set read_fds;
    device_connection_t *conn;
    rest_list_entry_t *conn_entry;
    const char *err_str;
    gnutls_dtls_prestate_st prestate;

//  to reduce code redundancy
    sock = context->connection_listen->sock;
//  set active file descriptors and calculate required nfds
    FD_ZERO(&read_fds);

    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_entry->next)
    {
        conn = (device_connection_t *)conn_entry->data;

        FD_SET(conn->sock, &read_fds);
        if (conn->sock >= nfds)
        {
            nfds = conn->sock + 1;
        }
    }

    FD_SET(sock, &read_fds);
    if (sock >= nfds)
    {
        nfds = sock + 1;
    }

    ret = select(nfds, &read_fds, NULL, NULL, tv);
    if (ret <= 0)
    {
        return ret;
    }

//  manage client connections
    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_entry->next)
    {
        conn = (device_connection_t *)conn_entry->data;

        if (FD_ISSET(conn->sock, &read_fds))
        {
            if (gnutls_session_get_desc(conn->session) == NULL)
            {
                ret = gnutls_handshake(conn->session);

                //handshake continues until success
                if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_SUCCESS)
                {
                    err_str = gnutls_strerror(ret);
                    log_message(LOG_LEVEL_WARN, "Handshake failed with message: '%s'\n", err_str);

                    connection_close_secure(context, conn);
                    return 0;
                }
            }
            else
            {
                conn->addr_size = sizeof(conn->addr);

                ret = recvfrom(conn->sock, buffer, size, MSG_PEEK,
                               (struct sockaddr *)&conn->addr, &conn->addr_size);
                ret = gnutls_record_recv(conn->session, buffer, ret);

                if (ret <= 0)
                {
                    connection_close_secure(context, conn);
                }

                *connection = conn;
                return ret;
            }
        }
    }

//  expecting a new client connection
    if (FD_ISSET(sock, &read_fds))
    {
        context->connection_listen->addr_size = sizeof(context->connection_listen->addr);

        //TODO: do MSG_PEEK so that same payload later goes to handshake
        //then need to clear buffer
        ret = recvfrom(sock, buffer, size, 0,
                       (struct sockaddr *)&context->connection_listen->addr, &context->connection_listen->addr_size);
        if (ret > 0)
        {
            memset(&prestate, 0, sizeof(gnutls_dtls_prestate_st));

            ret = gnutls_dtls_cookie_verify(&context->cookie_key, &context->connection_listen->addr,
                                            sizeof(context->connection_listen->addr), buffer, ret, &prestate);
            if (ret == GNUTLS_E_BAD_COOKIE)
            {
                gnutls_dtls_cookie_send(&context->cookie_key, &context->connection_listen->addr,
                                        sizeof(context->connection_listen->addr), &prestate, context->connection_listen, prv_net_send);
            }
            else if (ret == 0)
            {
                ret = -1;
                conn = context->connection_listen;

                context->connection_listen = prv_new_connection_listen(context);
                if (context->connection_listen == NULL)
                {
                    context->connection_listen = conn;
                    goto connect_fail;
                }

//              the current socket will be taken over by the client connection
                if (connect(conn->sock, (struct sockaddr *)&conn->addr, sizeof(conn->addr)))
                {
                    close(conn->sock);
                    free(conn);
                    goto connect_fail;
                }

                if (prv_connection_init(context, conn, &prestate))
                {
                    close(conn->sock);
                    free(conn);
                    goto connect_fail;
                }

                ret = 0;
connect_fail:
                if (ret)
                {
                    log_message(LOG_LEVEL_ERROR, "Failed to connect with new device\n");
                }
                else
                {
                    rest_list_add(context->connection_list, conn);
                }
            }
        }
    }

    return 0;
}

static int connection_close_secure(void *context_p, void *connection)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    device_connection_t *conn = (device_connection_t *)connection;
    int ret;

    if (conn == NULL)
    {
        return 0;
    }

    rest_list_remove(context->connection_list, conn);

    if (conn->session)
    {
        do
        {
            ret = gnutls_bye(conn->session, GNUTLS_SHUT_RDWR);
        } while (ret == GNUTLS_E_AGAIN);

        if (ret != GNUTLS_E_SUCCESS)
        {
            return -1;
        }
        gnutls_deinit(conn->session);
    }

    close(conn->sock);
    free(conn);
    return 0;
}

static int connection_send_secure(void *context_p, void *connection, uint8_t *buffer, size_t length)
{
    device_connection_t *conn = (device_connection_t *)connection;

    return gnutls_record_send(conn->session, buffer, length);
}

static int connection_stop_secure(void *context_p)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    device_connection_t *conn;
    rest_list_entry_t *conn_entry, *conn_next;

    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_next)
    {
        conn_next = conn_entry->next;
        conn = (device_connection_t *)conn_entry->data;

        if (connection_close_secure(context, conn))
        {
            log_message(LOG_LEVEL_ERROR, "Failed to deinit session with client\n");
        }
    }

    rest_list_delete(context->connection_list);

    gnutls_certificate_free_credentials(context->server_cert);
    gnutls_priority_deinit(context->priority_cache);
    gnutls_psk_free_server_credentials(context->server_psk);
    gnutls_global_deinit();

    close(context->connection_listen->sock);
    free(context->connection_listen);

    return 0;
}

static int connection_validate_secure(char *name, void *connection)
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
