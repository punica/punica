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

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/select.h>

#include "connection-secure.h"
#include <liblwm2m.h>

static mbedtls_connection_t* connectionList = NULL;

mbedtls_net_context listen_fd;
unsigned char* buf = 0;
int version_suites[4][2];
//TODO: MBEDTLS_PSK_MAX_LEN must be increased to 64 to satisfy RFC7925
unsigned char psk[MBEDTLS_PSK_MAX_LEN];
size_t psk_len = 0;
const char *pers = "ssl_server2";
unsigned char client_ip[16] = { 0 };
size_t cliip_len;
#if defined(MBEDTLS_SSL_COOKIE_C)
mbedtls_ssl_cookie_ctx cookie_ctx;
#endif

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
#if defined(MBEDTLS_TIMING_C)
mbedtls_timing_delay_context timer;
#endif
#if defined(MBEDTLS_SSL_RENEGOTIATION)
unsigned char renego_period[8] = { 0 };
#endif
#if defined(MBEDTLS_X509_CRT_PARSE_C)
uint32_t flags;
mbedtls_x509_crt cacert;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
int key_cert_init = 0;
#endif /* MBEDTLS_X509_CRT_PARSE_C */
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
mbedtls_dhm_context dhm;
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
mbedtls_ssl_cache_context cache;
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
mbedtls_ssl_ticket_context ticket_ctx;
#endif
#if defined(SNI_OPTION)
sni_entry *sni_info = NULL;
#endif
#if defined(MBEDTLS_ECP_C)
mbedtls_ecp_group_id curve_list[CURVE_LIST_SIZE];
const mbedtls_ecp_curve_info * curve_cur;
#endif

static struct mbedtls_options opt =
{
    .buffer_size         = 1024,
    .server_addr         = "localhost",
    .server_port         = 0,
    .debug_level         = 0,
    .event               = 0,
    .response_size       = -1,
    .nbio                = 0,
    .read_timeout        = 0,
    .ca_file             = "",
    .crt_file            = "",
    .key_file            = "",
    .async_operations    = "-",
    .async_private_delay1 = -1,
    .async_private_error = 0,
    .psk                 = "",
    .psk_identity        = "",
    .psk_cont            = NULL,
    .ecjpake_pw          = NULL,
    .force_ciphersuite[0]= 0,
    .version_suites      = NULL,
    .renegotiation       = MBEDTLS_SSL_RENEGOTIATION_DISABLED,
    .allow_legacy        = -2,
    .renegotiate         = 0,
    .renego_delay        = -2,
    .renego_period       = ((uint64_t)-1),
    .exchanges           = 1,
    .min_version         = -1,
    .max_version         = -1,
    .arc4                = -1,
    .allow_sha1          = -1,
    .auth_mode           = 1,
    .cert_req_ca_list    = MBEDTLS_SSL_CERT_REQ_CA_LIST_ENABLED,
    .mfl_code            = MBEDTLS_SSL_MAX_FRAG_LEN_NONE,
    .trunc_hmac          = -1,
    .tickets             = MBEDTLS_SSL_SESSION_TICKETS_ENABLED,
    .ticket_timeout      = 86400,
    .cache_max           = 1,
    .cache_timeout       = 1,
    .alpn_string         = NULL,
    .dhm_file            = NULL,
    .transport           = MBEDTLS_SSL_TRANSPORT_DATAGRAM,
    .cookies             = 1,
    .anti_replay         = -1,
    .hs_to_min           = 0,
    .hs_to_max           = 0,
    .dtls_mtu            = -1,
    .dgram_packing       = 1,
    .badmac_limit        = -1,
    .extended_ms         = -1,
    .etm                 = -1,
};

int connection_create_secure(settings_t *options, int addressFamily)
{
    int ret = 0;

//    opt.server_addr = options->server_addr;
    opt.server_port = options->coap.port;
    opt.debug_level = options->logging.level;
//    opt.auth_mode = options->auth_mode;
    opt.ca_file = options->coap.certificate_file;
    opt.crt_file = options->coap.certificate_file;
    opt.key_file = options->coap.private_key_file;
//    opt.psk = options->psk;
//    opt.psk_identity = options->psk_identity;
//  pass whole coap structure in case the HEAD of linked list 'coap.security' changes
    opt.psk_cont = &options->coap;

    mbedtls_net_init( &listen_fd );
    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_pk_init( &pkey );
#endif
#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
    mbedtls_dhm_init( &dhm );
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_ticket_init( &ticket_ctx );
#endif
#if defined(MBEDTLS_SSL_COOKIE_C)
    mbedtls_ssl_cookie_init( &cookie_ctx );
#endif

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( opt.debug_level );
#endif
    buf = calloc( 1, opt.buffer_size + 1 );
    if( buf == NULL )
    {
        return -1;
    }

    if( unhexify( psk, opt.psk, &psk_len ) != 0 )
    {
        return -1;
    }

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                       &entropy, (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        return -1;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if defined(MBEDTLS_FS_IO)
    if(opt.ca_file)
    {
        ret = mbedtls_x509_crt_parse_file(&cacert, opt.ca_file);
    }
    else
#endif
    if( ret < 0 )
    {
        return -1;
    }

#if defined(MBEDTLS_FS_IO)
    if(opt.crt_file)
    {
        key_cert_init++;
        if( ( ret = mbedtls_x509_crt_parse_file(&srvcert, opt.crt_file) ) != 0 )
        {
            fprintf(stderr, "mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret);
            return -1;
        }
    }
    if(opt.key_file)
    {
        key_cert_init++;
        if( (ret = mbedtls_pk_parse_keyfile(&pkey, opt.key_file, "") ) != 0 )
        {
            fprintf(stderr, "mbedtls_pk_parse_keyfile returned -0x%x\n\n", -ret );
            return -1;
        }
    }
    if( key_cert_init == 1 )
    {
        fprintf(stderr, "crt_file without key_file or vice-versa\n\n" );
        return -1;
    }
#endif
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_DHM_C) && defined(MBEDTLS_FS_IO)
    if( opt.dhm_file != NULL )
    {
        if( ( ret = mbedtls_dhm_parse_dhmfile( &dhm, opt.dhm_file ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_dhm_parse_dhmfile returned -0x%04X\n\n",
                     -ret );
            return -1;
        }

    }
#endif

#if defined(SNI_OPTION)
    if( opt.sni != NULL )
    {
        if( ( sni_info = sni_parse( opt.sni ) ) == NULL )
        {
            return -1;
        }

        printf( " ok\n" );
    }
#endif /* SNI_OPTION */

    char server_port_string[6];
    snprintf(server_port_string, sizeof(server_port_string), "%d", opt.server_port);

    if( ( ret = mbedtls_net_bind( &listen_fd, NULL, server_port_string, MBEDTLS_NET_PROTO_UDP ) ) != 0 )
    {
        fprintf(stderr, "mbedtls_net_bind returned -0x%x\n\n", -ret );
        return -1;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    opt.transport,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        fprintf(stderr, "mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret );
        return -1;
    }

    if(opt.auth_mode)
    {
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    }

    if( opt.cert_req_ca_list != DFL_CERT_REQ_CA_LIST )
        mbedtls_ssl_conf_cert_req_ca_list( &conf, opt.cert_req_ca_list );

#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    if( ( ret = mbedtls_ssl_conf_max_frag_len( &conf, opt.mfl_code ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ssl_conf_max_frag_len returned %d\n\n", ret );
        return -1;
    };
#endif

#if defined(MBEDTLS_SSL_TRUNCATED_HMAC)
    if( opt.trunc_hmac != DFL_TRUNC_HMAC )
        mbedtls_ssl_conf_truncated_hmac( &conf, opt.trunc_hmac );
#endif

#if defined(MBEDTLS_SSL_EXTENDED_MASTER_SECRET)
    if( opt.extended_ms != DFL_EXTENDED_MS )
        mbedtls_ssl_conf_extended_master_secret( &conf, opt.extended_ms );
#endif

#if defined(MBEDTLS_SSL_ENCRYPT_THEN_MAC)
    if( opt.etm != DFL_ETM )
        mbedtls_ssl_conf_encrypt_then_mac( &conf, opt.etm );
#endif

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );

#if defined(MBEDTLS_SSL_CACHE_C)
    if( opt.cache_max != -1 )
        mbedtls_ssl_cache_set_max_entries( &cache, opt.cache_max );

    if( opt.cache_timeout != -1 )
        mbedtls_ssl_cache_set_timeout( &cache, opt.cache_timeout );

    mbedtls_ssl_conf_session_cache( &conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set );
#endif

#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    if( opt.tickets == MBEDTLS_SSL_SESSION_TICKETS_ENABLED )
    {
        if( ( ret = mbedtls_ssl_ticket_setup( &ticket_ctx,
                        mbedtls_ctr_drbg_random, &ctr_drbg,
                        MBEDTLS_CIPHER_AES_256_GCM,
                        opt.ticket_timeout ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_ticket_setup returned %d\n\n", ret );
            return -1;
        }

        mbedtls_ssl_conf_session_tickets_cb( &conf,
                mbedtls_ssl_ticket_write,
                mbedtls_ssl_ticket_parse,
                &ticket_ctx );
    }
#endif

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM )
    {
#if defined(MBEDTLS_SSL_COOKIE_C)
        if( opt.cookies > 0 )
        {
            if( ( ret = mbedtls_ssl_cookie_setup( &cookie_ctx,
                                          mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
            {
                fprintf(stderr, "mbedtls_ssl_cookie_setup returned %d\n\n", ret );
                return -1;
            }

            mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                       &cookie_ctx );
        }
        else
#endif /* MBEDTLS_SSL_COOKIE_C */
#if defined(MBEDTLS_SSL_DTLS_HELLO_VERIFY)
        if( opt.cookies == 0 )
        {
            mbedtls_ssl_conf_dtls_cookies( &conf, NULL, NULL, NULL );
        }
        else
#endif /* MBEDTLS_SSL_DTLS_HELLO_VERIFY */
        {
            ; /* Nothing to do */
        }

#if defined(MBEDTLS_SSL_DTLS_ANTI_REPLAY)
        if( opt.anti_replay != DFL_ANTI_REPLAY )
            mbedtls_ssl_conf_dtls_anti_replay( &conf, opt.anti_replay );
#endif

#if defined(MBEDTLS_SSL_DTLS_BADMAC_LIMIT)
        if( opt.badmac_limit != DFL_BADMAC_LIMIT )
            mbedtls_ssl_conf_dtls_badmac_limit( &conf, opt.badmac_limit );
#endif
    }
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    if( opt.force_ciphersuite[0] != DFL_FORCE_CIPHER )
        mbedtls_ssl_conf_ciphersuites( &conf, opt.force_ciphersuite );

    if( opt.allow_legacy != DFL_ALLOW_LEGACY )
        mbedtls_ssl_conf_legacy_renegotiation( &conf, opt.allow_legacy );
#if defined(MBEDTLS_SSL_RENEGOTIATION)
    mbedtls_ssl_conf_renegotiation( &conf, opt.renegotiation );

    if( opt.renego_delay != DFL_RENEGO_DELAY )
        mbedtls_ssl_conf_renegotiation_enforced( &conf, opt.renego_delay );

    if( opt.renego_period != DFL_RENEGO_PERIOD )
    {
        PUT_UINT64_BE( renego_period, opt.renego_period, 0 );
        mbedtls_ssl_conf_renegotiation_period( &conf, renego_period );
    }
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
    if(opt.ca_file)
    {
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    }
    if( key_cert_init )
    {
        mbedtls_pk_context *pk = &pkey;
        if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, pk ) ) != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
            return -1;
        }
    }

#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(SNI_OPTION)
    if( opt.sni != NULL )
    {
        mbedtls_ssl_conf_sni( &conf, sni_callback, sni_info );
    }
#endif

#if defined(MBEDTLS_ECP_C)
    curve_list[0] = MBEDTLS_ECP_DP_SECP256R1;
    curve_list[1] = MBEDTLS_ECP_DP_NONE;
    mbedtls_ssl_conf_curves(&conf, curve_list);
#endif

    if( strlen( opt.psk ) != 0 && strlen( opt.psk_identity ) != 0 )
    {
        ret = mbedtls_ssl_conf_psk( &conf, psk, psk_len,
                           (const unsigned char *) opt.psk_identity,
                           strlen( opt.psk_identity ) );
        if( ret != 0 )
        {
            fprintf(stderr, "mbedtls_ssl_conf_psk returned -0x%04X\n\n", - ret );
            return -1;
        }
    }

    mbedtls_ssl_conf_psk_cb( &conf, psk_callback, opt.psk_cont );

#if defined(MBEDTLS_DHM_C)
    /*
     * Use different group than default DHM group
     */
#if defined(MBEDTLS_FS_IO)
    if( opt.dhm_file != NULL )
        ret = mbedtls_ssl_conf_dh_param_ctx( &conf, &dhm );
#endif
    if( ret != 0 )
    {
        fprintf(stderr, "mbedtls_ssl_conf_dh_param returned -0x%04X\n\n", - ret );
        return -1;
    }
#endif

    return 0;
}

static int prv_ssl_init(mbedtls_connection_t* connP)
{
    mbedtls_ssl_init(connP->ssl);
#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if(opt.dgram_packing != DFL_DGRAM_PACKING)
        mbedtls_ssl_set_datagram_packing(connP->ssl, opt.dgram_packing);
#endif /* MBEDTLS_SSL_PROTO_DTLS */

    mbedtls_ssl_set_bio(connP->ssl, connP->sock, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

//    ret = mbedtls_ssl_setup(&connP->ssl, &conf);
    mbedtls_ssl_setup(connP->ssl, &conf);

#if defined(MBEDTLS_SSL_PROTO_DTLS)
    if( opt.dtls_mtu != DFL_DTLS_MTU )
        mbedtls_ssl_set_mtu(connP->ssl, opt.dtls_mtu);
#endif
#if defined(MBEDTLS_TIMING_C)
    mbedtls_ssl_set_timer_cb(connP->ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
#endif

    mbedtls_ssl_session_reset(connP->ssl);

    return 0;
}

static mbedtls_connection_t * connection_new_incoming(void)
{
    mbedtls_connection_t * connP;

    connP = (mbedtls_connection_t *)malloc(sizeof(mbedtls_connection_t));
    if (connP != NULL)
    {
        connP->sock = (mbedtls_net_context*)malloc(sizeof(mbedtls_net_context));
        mbedtls_net_init(connP->sock);

        connP->ssl = (mbedtls_ssl_context*)malloc(sizeof(mbedtls_ssl_context));
        prv_ssl_init(connP);

        connP->next = connectionList;
        connectionList = connP;
    }

    return connP;
}

int connection_step_secure(void *ctx, struct timeval *tv)
{
    int ret, nfds = 0;
    fd_set read_fds;
    mbedtls_connection_t* connP_curr = connectionList;

    FD_ZERO(&read_fds);

    while(connP_curr != NULL)
    {
        FD_SET(connP_curr->sock->fd, &read_fds);
        if(connP_curr->sock->fd >= nfds)
        {
            nfds = connP_curr->sock->fd + 1;
        }
        connP_curr = connP_curr->next;
    }

    FD_SET(listen_fd.fd, &read_fds);
    if(listen_fd.fd >= nfds)
    {
        nfds = listen_fd.fd + 1;
    }

    ret = select(nfds, &read_fds, NULL, NULL, tv);
    if(ret < 0)
    {
//      errno
        return ret;
    }
    else if(ret == 0)
    {
//      keep this in case we want to manage ret < 0 error
        return ret;
    }

    connP_curr = connectionList;
    while(connP_curr != NULL)
    {
        if(FD_ISSET(connP_curr->sock->fd, &read_fds))
        {
            ret = mbedtls_ssl_read(connP_curr->ssl, buf, opt.buffer_size - 1);
            if(ret > 0)
            {
                lwm2m_handle_packet(ctx, buf, ret, connP_curr);
            }
        }
        connP_curr = connP_curr->next;
    }

    if(FD_ISSET(listen_fd.fd, &read_fds))
    {
        mbedtls_connection_t* connP = connection_new_incoming();
        unsigned char client_ip[16] = { 0 };
        size_t cliip_len;

hello_verify:
        mbedtls_net_accept(&listen_fd, connP->sock, client_ip, sizeof(client_ip), &cliip_len);
        mbedtls_ssl_set_client_transport_id(connP->ssl, client_ip, cliip_len);

        ret = mbedtls_ssl_read(connP->ssl, buf, opt.buffer_size - 1);
        if(ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
        {
            mbedtls_net_free(connP->sock);
            mbedtls_ssl_session_reset(connP->ssl);
            goto hello_verify;
        }
        else if(ret > 0)
        {
            lwm2m_handle_packet(ctx, buf, ret, connP);
        }
        else
        {
            connection_free_secure(connP);
        }
    }

    return 0;
}

void connection_free_secure(void *connection)
{
    mbedtls_connection_t *connP = (mbedtls_connection_t *)connection;

    if(connectionList == NULL)
    {
        return;
    }

    if(connP == connectionList)
    {
        connectionList = connP->next;
        goto free;
    }

    mbedtls_connection_t* connP_curr = connectionList;

    do
    {
        if(connP_curr->next == connP)
        {
            connP_curr->next = connP->next;
            goto free;
        }
        connP_curr = connP_curr->next;
    }
    while (connP_curr->next != NULL);

free:
//  check if NULL to avoid double free?
    mbedtls_ssl_close_notify(connP->ssl);
    mbedtls_net_free(connP->sock);
    free(connP->sock);
    mbedtls_ssl_free(connP->ssl);
    free(connP->ssl);
    free(connP);
}

uint8_t lwm2m_buffer_send(void * sessionH,
                          uint8_t * buffer,
                          size_t length,
                          void * userdata)
{
    mbedtls_connection_t * connP = (mbedtls_connection_t*) sessionH;

    if (connP == NULL)
    {
        fprintf(stderr, "#> failed sending %lu bytes, missing connection\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    if(mbedtls_ssl_write(connP->ssl, buffer, length) < 0)
    {
        fprintf(stderr, "#> failed sending %lu bytes\r\n", length);
        return COAP_500_INTERNAL_SERVER_ERROR ;
    }

    return COAP_NO_ERROR;
}

bool lwm2m_session_is_equal(void * session1,
                            void * session2,
                            void * userData)
{
    return (session1 == session2);
}
