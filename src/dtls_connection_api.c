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

#include "dtls_connection_api.h"
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <gnutls/dtls.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "database.h"
#include "linked_list.h"

#define BUFFER_SIZE 1024

typedef struct _device_connection_t
{
    int sock;
    gnutls_session_t session;
    struct sockaddr_storage addr;
    socklen_t addr_size;
    void *device_identifier;
    bool handshake_done;
} device_connection_t;

typedef struct secure_connection_context_t
{
    connection_api_t api;
    linked_list_t *connection_list;
    device_connection_t *conn_listen;
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
    f_handshake_done_cb_t handshake_done_cb;
} secure_connection_context_t;

static int dtls_connection_start(void *context_p);
static int dtls_connection_receive(void *context_p, uint8_t *buffer, size_t size,
                                   session_t *connection,
                                   struct timeval *tv);
static int dtls_connection_send(void *context_p, session_t connection, uint8_t *buffer,
                                size_t length);
static int dtls_connection_close(void *context_p, session_t connection);
static int dtls_connection_stop(void *context_p);

static credentials_mode_t get_session_ciphersuite(gnutls_session_t session)
{
    gnutls_cipher_algorithm_t cipher;
    gnutls_kx_algorithm_t key_ex;

    cipher = gnutls_cipher_get(session);
    key_ex = gnutls_kx_get(session);

    if (key_ex == GNUTLS_KX_ECDHE_ECDSA
        && (cipher == GNUTLS_CIPHER_AES_128_CCM_8
            || cipher == GNUTLS_CIPHER_AES_128_CBC))
    {
        return DEVICE_CREDENTIALS_CERT;
    }
    else if (key_ex == GNUTLS_KX_PSK
             && (cipher == GNUTLS_CIPHER_AES_128_CCM_8
                 || cipher == GNUTLS_CIPHER_AES_128_CBC))
    {
        return DEVICE_CREDENTIALS_PSK;
    }
    else
    {
        return DEVICE_CREDENTIALS_UNDEFINED;
    }
}

static const void *dtls_connection_get_identifier(session_t connection)
{
    device_connection_t *conn = (device_connection_t *)connection;

    if (conn == NULL)
    {
        return NULL;
    }

    return conn->device_identifier;
}

static int dtls_connection_set_identifier(session_t connection, void *identifier)
{
    device_connection_t *conn = (device_connection_t *)connection;

    if (conn == NULL)
    {
        return -1;
    }

    conn->device_identifier = identifier;
    return 0;
}

static int dtls_connection_handshake_done(device_connection_t *conn,
                                          credentials_mode_t ciphersuite)
{
    void *public_data;
    gnutls_x509_crt_t cert;
    const gnutls_datum_t *cert_list;
    size_t public_data_size = 0;
    secure_connection_context_t *context;
    int ret;

    context = gnutls_session_get_ptr(conn->session);

    if (ciphersuite == DEVICE_CREDENTIALS_PSK)
    {
        public_data = (void *)gnutls_psk_server_get_username(conn->session);
        if (public_data == NULL)
        {
            return -1;
        }

        public_data_size = strlen(public_data);
    }
    else if (ciphersuite == DEVICE_CREDENTIALS_CERT)
    {
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
            gnutls_x509_crt_deinit(cert);
            return -1;
        }

        gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, NULL, &public_data_size);

        public_data = malloc(public_data_size);
        if (public_data == NULL)
        {
            gnutls_x509_crt_deinit(cert);
            return -1;
        }
        if (gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, public_data, &public_data_size))
        {
            free(public_data);
            gnutls_x509_crt_deinit(cert);
            return -1;
        }

        gnutls_x509_crt_deinit(cert);
    }
    else
    {
        return -1;
    }

    ret = context->handshake_done_cb(conn, public_data, public_data_size, context->data);

    if (ciphersuite == DEVICE_CREDENTIALS_CERT)
    {
        free(public_data);
    }

    conn->handshake_done = true;

    return ret;
}

static ssize_t dtls_connection_net_send(gnutls_transport_ptr_t context, const void *data,
                                        size_t size)
{
    device_connection_t *conn = (device_connection_t *)context;

    return sendto(conn->sock, data, size, 0, (struct sockaddr *)&conn->addr, conn->addr_size);
}

static ssize_t dtls_connection_net_recv(gnutls_transport_ptr_t context, void *data, size_t size)
{
    device_connection_t *conn = (device_connection_t *)context;
    int ret;
    struct sockaddr addr;
    socklen_t addr_size;

    addr_size = sizeof(addr);
    ret = recvfrom(conn->sock, data, size, 0, &addr, &addr_size);
    if (ret < 0)
    {
        return ret;
    }

    if (addr_size == conn->addr_size
        && memcmp(&addr, &conn->addr, sizeof(addr)) == 0)
    {
        return ret;
    }

    gnutls_transport_set_errno(conn->session, EAGAIN);

    return -1;
}

static int dtls_connection_net_recv_timeout(gnutls_transport_ptr_t context, unsigned int ms)
{
    device_connection_t *conn = (device_connection_t *)context;
    struct timeval tv;
    fd_set fd;
    int ret;
    uint8_t buffer[1024];
    size_t buffer_length;
    struct sockaddr addr;
    socklen_t addr_size;

    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;

    FD_ZERO(&fd);
    FD_SET(conn->sock, &fd);

    ret = select(conn->sock + 1, &fd, NULL, NULL, &tv);
    if (ret <= 0)
    {
        return ret;
    }

    buffer_length = sizeof(buffer);
    addr_size = sizeof(addr);

    ret = recvfrom(conn->sock, buffer, buffer_length, MSG_PEEK, &addr, &addr_size);
    if (ret < 0)
    {
        return ret;
    }

    if (addr_size == conn->addr_size
        && memcmp(&addr, &conn->addr, sizeof(addr)) == 0)
    {
        return ret;
    }

    gnutls_transport_set_errno(conn->session, EAGAIN);

    return -1;
}

static int dtls_connection_new_socket(secure_connection_context_t *context)
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

static int dtls_connection_init(secure_connection_context_t *context,
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

    gnutls_transport_set_ptr(connection->session, connection);
    gnutls_transport_set_push_function(connection->session, dtls_connection_net_send);
    gnutls_transport_set_pull_function(connection->session, dtls_connection_net_recv);
    gnutls_transport_set_pull_timeout_function(connection->session, dtls_connection_net_recv_timeout);

    gnutls_session_set_ptr(connection->session, context);

    ret = 0;
exit:
    if (ret)
    {
        gnutls_deinit(connection->session);
    }
    return ret;
}

static int dtls_connection_psk_callback(gnutls_session_t session, const char *name,
                                        gnutls_datum_t *key)
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

static device_connection_t *dtls_connection_new_listen(secure_connection_context_t *context)
{
    device_connection_t *conn;

    conn = calloc(1, sizeof(device_connection_t));
    if (conn == NULL)
    {
        return NULL;
    }

    conn->sock = dtls_connection_new_socket(context);
    if (conn->sock <= 0)
    {
        free(conn);
        return NULL;
    }

    return conn;
}

connection_api_t *dtls_connection_api_init(int port, int address_family,
                                           const char *certificate_file,
                                           const char *private_key_file,
                                           void *data, f_psk_cb_t psk_cb,
                                           f_handshake_done_cb_t handshake_done_cb)
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
    context->handshake_done_cb = handshake_done_cb;

    context->api.f_start = dtls_connection_start;
    context->api.f_receive = dtls_connection_receive;
    context->api.f_send = dtls_connection_send;
    context->api.f_close = dtls_connection_close;
    context->api.f_stop = dtls_connection_stop;
    context->api.f_get_identifier = dtls_connection_get_identifier;
    context->api.f_set_identifier = dtls_connection_set_identifier;

    return &context->api;
}

void dtls_connection_api_deinit(void *context_p)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;

    free(context);
}

static int dtls_connection_start(void *context_p)
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

    context->connection_list = linked_list_new();
    if (context->connection_list == NULL)
    {
        goto exit;
    }

    context->conn_listen = dtls_connection_new_listen(context);
    if (context->conn_listen == NULL)
    {
        linked_list_delete(context->connection_list);
        goto exit;
    }

    gnutls_psk_set_server_credentials_function(context->server_psk, dtls_connection_psk_callback);

    ret = context->conn_listen->sock;

exit:
    if (ret <= 0)
    {
        gnutls_free(context->cookie_key.data);
        gnutls_certificate_free_credentials(context->server_cert);
        gnutls_priority_deinit(context->priority_cache);
        gnutls_psk_free_server_credentials(context->server_psk);
    }
    return ret;
}

static device_connection_t *dtls_connection_new_incoming(secure_connection_context_t *context,
                                                         gnutls_dtls_prestate_st *prestate)
{
    device_connection_t *conn;

    conn = calloc(1, sizeof(device_connection_t));
    if (conn == NULL)
    {
        return NULL;
    }

    conn->sock = context->conn_listen->sock;
    memcpy(&conn->addr, &context->conn_listen->addr, sizeof(struct sockaddr_storage));
    memcpy(&conn->addr_size, &context->conn_listen->addr_size, sizeof(socklen_t));
    conn->handshake_done = false;

    if (dtls_connection_init(context, conn, prestate))
    {
        free(conn);
        return NULL;
    }

    return conn;
}

static device_connection_t *dtls_connection_find(linked_list_t *connection_list,
                                                 const struct sockaddr_storage *addr, const socklen_t addr_size)
{
    device_connection_t *conn;
    linked_list_entry_t *conn_entry;

    for (conn_entry = connection_list->head; conn_entry != NULL; conn_entry = conn_entry->next)
    {
        conn = (device_connection_t *)conn_entry->data;

        if (conn->addr_size == addr_size
            && memcmp(&conn->addr, addr, addr_size) == 0)
        {
            return conn;
        }
    }

    return NULL;
}

static int dtls_connection_receive(void *context_p, uint8_t *buffer, size_t size,
                                   session_t *connection, struct timeval *tv)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    fd_set read_fds;
    int ret, sock;
    device_connection_t *conn;
    gnutls_dtls_prestate_st prestate;
    credentials_mode_t ciphersuite;
    const char *err_str;
    char *session_desc = NULL;

//  to reduce code redundancy
    sock = context->conn_listen->sock;

    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);

    ret = select(sock + 1, &read_fds, NULL, NULL, tv);
    if (ret <= 0)
    {
        return ret;
    }

    if (FD_ISSET(sock, &read_fds))
    {
        context->conn_listen->addr_size = sizeof(context->conn_listen->addr);

        ret = recvfrom(sock, buffer, size, MSG_PEEK, (struct sockaddr *)&context->conn_listen->addr,
                       &context->conn_listen->addr_size);
        if (ret > 0)
        {
            conn = dtls_connection_find(context->connection_list, &context->conn_listen->addr,
                                        context->conn_listen->addr_size);

            if (conn == NULL)
            {
                memset(&prestate, 0, sizeof(gnutls_dtls_prestate_st));

                ret = gnutls_dtls_cookie_verify(&context->cookie_key, &context->conn_listen->addr,
                                                sizeof(context->conn_listen->addr), buffer, ret, &prestate);

                if (ret == GNUTLS_E_BAD_COOKIE)
                {
                    gnutls_dtls_cookie_send(&context->cookie_key, &context->conn_listen->addr,
                                            sizeof(context->conn_listen->addr), &prestate, context->conn_listen, dtls_connection_net_send);
                    recvfrom(sock, buffer, size, 0, NULL, NULL);
                }
                else if (ret == GNUTLS_E_SUCCESS)
                {
                    conn = dtls_connection_new_incoming(context, &prestate);
                    if (conn != NULL)
                    {
                        linked_list_add(context->connection_list, conn);
                    }
                    else
                    {
                        log_message(LOG_LEVEL_ERROR, "Failed to connect with new device\n");
                    }
                }
                else
                {
                    recvfrom(sock, buffer, size, 0, NULL, NULL);
                }
            }

            if (conn != NULL)
            {
                if (conn->handshake_done == false)
                {
                    ret = gnutls_handshake(conn->session);

                    //handshake continues until success
                    if (ret == GNUTLS_E_SUCCESS)
                    {
                        ciphersuite = get_session_ciphersuite(conn->session);

                        if (dtls_connection_handshake_done(conn, ciphersuite))
                        {
                            log_message(LOG_LEVEL_WARN, "Failed to store connection identifier\n");
                            dtls_connection_close(context, conn);
                        }

                        return 0;
                    }
                    else if (ret != GNUTLS_E_AGAIN)
                    {
                        err_str = gnutls_strerror(ret);
                        log_message(LOG_LEVEL_WARN, "Handshake failed with message: '%s'\n", err_str);

                        dtls_connection_close(context, conn);
                        return 0;
                    }
                }
                else
                {
                    conn->addr_size = sizeof(conn->addr);

                    do
                    {
                        ret = recvfrom(conn->sock, buffer, size, MSG_PEEK, (struct sockaddr *)&conn->addr,
                                       &conn->addr_size);
                        ret = gnutls_record_recv(conn->session, buffer, ret);
                    } while (ret == GNUTLS_E_AGAIN);

                    if (ret < 0)
                    {
                        dtls_connection_close(context, conn);
                        ret = 0;
                    }
                    else
                    {
                        *connection = conn;
                    }

                    return ret;
                }
            }
        }
    }

    return 0;
}

static int dtls_connection_close(void *context_p, session_t connection)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    device_connection_t *conn = (device_connection_t *)connection;
    int ret;

    if (conn == NULL)
    {
        return 0;
    }

    linked_list_remove(context->connection_list, conn);

    if (conn->session)
    {
        do
        {
            ret = gnutls_bye(conn->session, GNUTLS_SHUT_WR);
        } while (ret == GNUTLS_E_AGAIN);

        if (ret != GNUTLS_E_SUCCESS)
        {
            return -1;
        }
        gnutls_deinit(conn->session);
    }

    free(conn);
    return 0;
}

static int dtls_connection_send(void *context_p, session_t connection, uint8_t *buffer,
                                size_t length)
{
    device_connection_t *conn = (device_connection_t *)connection;

    return gnutls_record_send(conn->session, buffer, length);
}

static int dtls_connection_stop(void *context_p)
{
    secure_connection_context_t *context = (secure_connection_context_t *)context_p;
    device_connection_t *conn;
    linked_list_entry_t *conn_entry, *conn_next;

    for (conn_entry = context->connection_list->head; conn_entry != NULL; conn_entry = conn_next)
    {
        conn_next = conn_entry->next;
        conn = (device_connection_t *)conn_entry->data;

        if (dtls_connection_close(context, conn))
        {
            log_message(LOG_LEVEL_ERROR, "Failed to deinit session with client\n");
        }
    }

    linked_list_delete(context->connection_list);

    gnutls_free(context->cookie_key.data);
    gnutls_certificate_free_credentials(context->server_cert);
    gnutls_priority_deinit(context->priority_cache);
    gnutls_psk_free_server_credentials(context->server_psk);
    gnutls_global_deinit();

    close(context->conn_listen->sock);
    free(context->conn_listen);

    return 0;
}
