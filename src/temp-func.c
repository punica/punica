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

#include "mbedtlsconnection.h"

void my_debug( void *ctx, int level, const char *file, int line, const char *str )
{
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    fprintf( (FILE *) ctx, "%s:%04d: |%d| %s", basename, line, level, str );
    fflush(  (FILE *) ctx  );
}

/*
 * Return authmode from string, or -1 on error
 */
int get_auth_mode( const char *s )
{
    if( strcmp( s, "none" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_NONE );
    if( strcmp( s, "optional" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_OPTIONAL );
    if( strcmp( s, "required" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_REQUIRED );

    return( -1 );
}

/*
 * Used by sni_parse to handle coma-separated lists
 */
#define GET_ITEM( dst )         \
    dst = p;                    \
    while( *p != ',' )          \
        if( ++p > end )         \
            goto error;         \
    *p++ = '\0';

#if defined(SNI_OPTION)
void sni_free( sni_entry *head )
{
    sni_entry *cur = head, *next;

    while( cur != NULL )
    {
        mbedtls_x509_crt_free( cur->cert );
        free( cur->cert );

        mbedtls_pk_free( cur->key );
        free( cur->key );

        mbedtls_x509_crt_free( cur->ca );
        free( cur->ca );

        mbedtls_x509_crl_free( cur->crl );
        free( cur->crl );

        next = cur->next;
        free( cur );
        cur = next;
    }
}

/*
 * Parse a string of sextuples name1,crt1,key1,ca1,crl1,auth1[,...]
 * into a usable sni_entry list. For ca1, crl1, auth1, the special value
 * '-' means unset. If ca1 is unset, then crl1 is ignored too.
 *
 * Modifies the input string! This is not production quality!
 */
sni_entry *sni_parse( char *sni_string )
{
    sni_entry *cur = NULL, *new = NULL;
    char *p = sni_string;
    char *end = p;
    char *crt_file, *key_file, *ca_file, *crl_file, *auth_str;

    while( *end != '\0' )
        ++end;
    *end = ',';

    while( p <= end )
    {
        if( ( new = calloc( 1, sizeof( sni_entry ) ) ) == NULL )
        {
            sni_free( cur );
            return( NULL );
        }

        GET_ITEM( new->name );
        GET_ITEM( crt_file );
        GET_ITEM( key_file );
        GET_ITEM( ca_file );
        GET_ITEM( crl_file );
        GET_ITEM( auth_str );

        if( ( new->cert = calloc( 1, sizeof( mbedtls_x509_crt ) ) ) == NULL ||
            ( new->key = calloc( 1, sizeof( mbedtls_pk_context ) ) ) == NULL )
            goto error;

        mbedtls_x509_crt_init( new->cert );
        mbedtls_pk_init( new->key );

        if( mbedtls_x509_crt_parse_file( new->cert, crt_file ) != 0 ||
            mbedtls_pk_parse_keyfile( new->key, key_file, "" ) != 0 )
            goto error;

        if( strcmp( ca_file, "-" ) != 0 )
        {
            if( ( new->ca = calloc( 1, sizeof( mbedtls_x509_crt ) ) ) == NULL )
                goto error;

            mbedtls_x509_crt_init( new->ca );

            if( mbedtls_x509_crt_parse_file( new->ca, ca_file ) != 0 )
                goto error;
        }

        if( strcmp( crl_file, "-" ) != 0 )
        {
            if( ( new->crl = calloc( 1, sizeof( mbedtls_x509_crl ) ) ) == NULL )
                goto error;

            mbedtls_x509_crl_init( new->crl );

            if( mbedtls_x509_crl_parse_file( new->crl, crl_file ) != 0 )
                goto error;
        }

        if( strcmp( auth_str, "-" ) != 0 )
        {
            if( ( new->authmode = get_auth_mode( auth_str ) ) < 0 )
                goto error;
        }
        else
            new->authmode = DFL_AUTH_MODE;

        new->next = cur;
        cur = new;
    }

    return( cur );

error:
    sni_free( new );
    sni_free( cur );
    return( NULL );
}

/*
 * SNI callback.
 */
int sni_callback( void *p_info, mbedtls_ssl_context *ssl,
                  const unsigned char *name, size_t name_len )
{
    const sni_entry *cur = (const sni_entry *) p_info;

    while( cur != NULL )
    {
        if( name_len == strlen( cur->name ) &&
            memcmp( name, cur->name, name_len ) == 0 )
        {
            if( cur->ca != NULL )
                mbedtls_ssl_set_hs_ca_chain( ssl, cur->ca, cur->crl );

            if( cur->authmode != DFL_AUTH_MODE )
                mbedtls_ssl_set_hs_authmode( ssl, cur->authmode );

            return( mbedtls_ssl_set_hs_own_cert( ssl, cur->cert, cur->key ) );
        }

        cur = cur->next;
    }

    return( -1 );
}

#endif /* SNI_OPTION */

#if defined(MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED)
/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int unhexify( unsigned char *output, const char *input, size_t *olen )
{
    unsigned char c;
    size_t j;

    *olen = strlen( input );
    if( *olen % 2 != 0 || *olen / 2 > MBEDTLS_PSK_MAX_LEN )
        return( -1 );
    *olen /= 2;

    for( j = 0; j < *olen * 2; j += 2 )
    {
        c = input[j];
        HEX2NUM( c );
        output[ j / 2 ] = c << 4;

        c = input[j + 1];
        HEX2NUM( c );
        output[ j / 2 ] |= c;
    }

    return( 0 );
}
#endif /* MBEDTLS_KEY_EXCHANGE__SOME__PSK_ENABLED */

int mbedtls_status_is_ssl_in_progress( int ret )
{
    return( ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE ||
            ret == MBEDTLS_ERR_SSL_ASYNC_IN_PROGRESS );
}


#if !defined(MBEDTLS_TIMING_C)
int idle( mbedtls_net_context *fd,
          int idle_reason )
#else
int idle( mbedtls_net_context *fd,
          mbedtls_timing_delay_context *timer,
          int idle_reason )
#endif
{
    int ret;
    int poll_type = 0;

    if( idle_reason == MBEDTLS_ERR_SSL_WANT_WRITE )
        poll_type = MBEDTLS_NET_POLL_WRITE;
    else if( idle_reason == MBEDTLS_ERR_SSL_WANT_READ )
        poll_type = MBEDTLS_NET_POLL_READ;
#if !defined(MBEDTLS_TIMING_C)
    else
        return( 0 );
#endif

    while( 1 )
    {
        /* Check if timer has expired */
#if defined(MBEDTLS_TIMING_C)
        if( timer != NULL &&
            mbedtls_timing_get_delay( timer ) == 2 )
        {
            break;
        }
#endif /* MBEDTLS_TIMING_C */

        /* Check if underlying transport became available */
        if( poll_type != 0 )
        {
            ret = mbedtls_net_poll( fd, poll_type, 0 );
            if( ret < 0 )
                return( ret );
            if( ret == poll_type )
                break;
        }
    }

    return( 0 );
}



