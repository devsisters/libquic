#include <boringssl/bssl.h>
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * ECC cipher suite support in OpenSSL originally developed by 
 * SUN MICROSYSTEMS, INC., and contributed to the OpenSSL project.
 */
/* ====================================================================
 * Copyright 2005 Nokia. All rights reserved.
 *
 * The portions of the attached software ("Contribution") is developed by
 * Nokia Corporation and is licensed pursuant to the OpenSSL open source
 * license.
 *
 * The Contribution, originally written by Mika Kousa and Pasi Eronen of
 * Nokia Corporation, consists of the "PSK" (Pre-Shared Key) ciphersuites
 * support (see RFC 4279) to OpenSSL.
 *
 * No patent licenses or other rights except those expressly stated in
 * the OpenSSL open source license shall be deemed granted or received
 * expressly, by implication, estoppel, or otherwise.
 *
 * No assurances are provided by Nokia that the Contribution does not
 * infringe the patent or other intellectual property rights of any third
 * party or that the license provides you with all the necessary rights
 * to make use of the Contribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND. IN
 * ADDITION TO THE DISCLAIMERS INCLUDED IN THE LICENSE, NOKIA
 * SPECIFICALLY DISCLAIMS ANY LIABILITY FOR CLAIMS BROUGHT BY YOU OR ANY
 * OTHER ENTITY BASED ON INFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS OR
 * OTHERWISE. */

#include <boringssl/ssl.h>

#include <assert.h>
#include <string.h>

#include <boringssl/bytestring.h>
#include <boringssl/crypto.h>
#include <boringssl/dh.h>
#include <boringssl/err.h>
#include <boringssl/lhash.h>
#include <boringssl/mem.h>
#include <boringssl/rand.h>
#include <boringssl/x509v3.h>

#include "internal.h"
#include "../crypto/internal.h"


/* |SSL_R_UNKNOWN_PROTOCOL| is no longer emitted, but continue to define it
 * to avoid downstream churn. */
OPENSSL_DECLARE_ERROR_REASON(SSL, UNKNOWN_PROTOCOL)

/* Some error codes are special. Ensure the make_errors.go script never
 * regresses this. */
OPENSSL_COMPILE_ASSERT(SSL_R_TLSV1_ALERT_NO_RENEGOTIATION ==
                           SSL_AD_NO_RENEGOTIATION + SSL_AD_REASON_OFFSET,
                       ssl_alert_reason_code_mismatch);

/* kMaxHandshakeSize is the maximum size, in bytes, of a handshake message. */
static const size_t kMaxHandshakeSize = (1u << 24) - 1;

static CRYPTO_EX_DATA_CLASS g_ex_data_class_ssl =
    CRYPTO_EX_DATA_CLASS_INIT_WITH_APP_DATA;
static CRYPTO_EX_DATA_CLASS g_ex_data_class_ssl_ctx =
    CRYPTO_EX_DATA_CLASS_INIT_WITH_APP_DATA;

int SSL_library_init(void) {
  CRYPTO_library_init();
  return 1;
}

static uint32_t ssl_session_hash(const SSL_SESSION *sess) {
  const uint8_t *session_id = sess->session_id;

  uint8_t tmp_storage[sizeof(uint32_t)];
  if (sess->session_id_length < sizeof(tmp_storage)) {
    memset(tmp_storage, 0, sizeof(tmp_storage));
    memcpy(tmp_storage, sess->session_id, sess->session_id_length);
    session_id = tmp_storage;
  }

  uint32_t hash =
      ((uint32_t)session_id[0]) |
      ((uint32_t)session_id[1] << 8) |
      ((uint32_t)session_id[2] << 16) |
      ((uint32_t)session_id[3] << 24);

  return hash;
}

/* NB: If this function (or indeed the hash function which uses a sort of
 * coarser function than this one) is changed, ensure
 * SSL_CTX_has_matching_session_id() is checked accordingly. It relies on being
 * able to construct an SSL_SESSION that will collide with any existing session
 * with a matching session ID. */
static int ssl_session_cmp(const SSL_SESSION *a, const SSL_SESSION *b) {
  if (a->ssl_version != b->ssl_version) {
    return 1;
  }

  if (a->session_id_length != b->session_id_length) {
    return 1;
  }

  return memcmp(a->session_id, b->session_id, a->session_id_length);
}

SSL_CTX *SSL_CTX_new(const SSL_METHOD *method) {
  SSL_CTX *ret = NULL;

  if (method == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NULL_SSL_METHOD_PASSED);
    return NULL;
  }

  if (SSL_get_ex_data_X509_STORE_CTX_idx() < 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_X509_VERIFICATION_SETUP_PROBLEMS);
    goto err;
  }

  ret = OPENSSL_malloc(sizeof(SSL_CTX));
  if (ret == NULL) {
    goto err;
  }

  memset(ret, 0, sizeof(SSL_CTX));

  ret->method = method->method;

  CRYPTO_MUTEX_init(&ret->lock);

  ret->session_cache_mode = SSL_SESS_CACHE_SERVER;
  ret->session_cache_size = SSL_SESSION_CACHE_MAX_SIZE_DEFAULT;

  /* We take the system default */
  ret->session_timeout = SSL_DEFAULT_SESSION_TIMEOUT;

  ret->references = 1;

  ret->max_cert_list = SSL_MAX_CERT_LIST_DEFAULT;
  ret->verify_mode = SSL_VERIFY_NONE;
  ret->cert = ssl_cert_new();
  if (ret->cert == NULL) {
    goto err;
  }

  ret->sessions = lh_SSL_SESSION_new(ssl_session_hash, ssl_session_cmp);
  if (ret->sessions == NULL) {
    goto err;
  }
  ret->cert_store = X509_STORE_new();
  if (ret->cert_store == NULL) {
    goto err;
  }

  ssl_create_cipher_list(ret->method, &ret->cipher_list,
                         &ret->cipher_list_by_id, SSL_DEFAULT_CIPHER_LIST);
  if (ret->cipher_list == NULL ||
      sk_SSL_CIPHER_num(ret->cipher_list->ciphers) <= 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_LIBRARY_HAS_NO_CIPHERS);
    goto err2;
  }

  ret->param = X509_VERIFY_PARAM_new();
  if (!ret->param) {
    goto err;
  }

  ret->client_CA = sk_X509_NAME_new_null();
  if (ret->client_CA == NULL) {
    goto err;
  }

  CRYPTO_new_ex_data(&ret->ex_data);

  ret->max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;

  /* Setup RFC4507 ticket keys */
  if (!RAND_bytes(ret->tlsext_tick_key_name, 16) ||
      !RAND_bytes(ret->tlsext_tick_hmac_key, 16) ||
      !RAND_bytes(ret->tlsext_tick_aes_key, 16)) {
    ret->options |= SSL_OP_NO_TICKET;
  }

  /* Lock the SSL_CTX to the specified version, for compatibility with legacy
   * uses of SSL_METHOD. */
  if (method->version != 0) {
    SSL_CTX_set_max_version(ret, method->version);
    SSL_CTX_set_min_version(ret, method->version);
  }

  return ret;

err:
  OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
err2:
  SSL_CTX_free(ret);
  return NULL;
}

void SSL_CTX_free(SSL_CTX *ctx) {
  if (ctx == NULL ||
      !CRYPTO_refcount_dec_and_test_zero(&ctx->references)) {
    return;
  }

  X509_VERIFY_PARAM_free(ctx->param);

  /* Free internal session cache. However: the remove_cb() may reference the
   * ex_data of SSL_CTX, thus the ex_data store can only be removed after the
   * sessions were flushed. As the ex_data handling routines might also touch
   * the session cache, the most secure solution seems to be: empty (flush) the
   * cache, then free ex_data, then finally free the cache. (See ticket
   * [openssl.org #212].) */
  SSL_CTX_flush_sessions(ctx, 0);

  CRYPTO_free_ex_data(&g_ex_data_class_ssl_ctx, ctx, &ctx->ex_data);

  CRYPTO_MUTEX_cleanup(&ctx->lock);
  lh_SSL_SESSION_free(ctx->sessions);
  X509_STORE_free(ctx->cert_store);
  ssl_cipher_preference_list_free(ctx->cipher_list);
  sk_SSL_CIPHER_free(ctx->cipher_list_by_id);
  ssl_cipher_preference_list_free(ctx->cipher_list_tls10);
  ssl_cipher_preference_list_free(ctx->cipher_list_tls11);
  ssl_cert_free(ctx->cert);
  sk_SSL_CUSTOM_EXTENSION_pop_free(ctx->client_custom_extensions,
                                   SSL_CUSTOM_EXTENSION_free);
  sk_SSL_CUSTOM_EXTENSION_pop_free(ctx->server_custom_extensions,
                                   SSL_CUSTOM_EXTENSION_free);
  sk_X509_NAME_pop_free(ctx->client_CA, X509_NAME_free);
  sk_SRTP_PROTECTION_PROFILE_free(ctx->srtp_profiles);
  OPENSSL_free(ctx->psk_identity_hint);
  OPENSSL_free(ctx->tlsext_ellipticcurvelist);
  OPENSSL_free(ctx->alpn_client_proto_list);
  OPENSSL_free(ctx->ocsp_response);
  OPENSSL_free(ctx->signed_cert_timestamp_list);
  EVP_PKEY_free(ctx->tlsext_channel_id_private);

  OPENSSL_free(ctx);
}

SSL *SSL_new(SSL_CTX *ctx) {
  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NULL_SSL_CTX);
    return NULL;
  }
  if (ctx->method == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_CTX_HAS_NO_DEFAULT_SSL_VERSION);
    return NULL;
  }

  SSL *ssl = OPENSSL_malloc(sizeof(SSL));
  if (ssl == NULL) {
    goto err;
  }
  memset(ssl, 0, sizeof(SSL));

  ssl->min_version = ctx->min_version;
  ssl->max_version = ctx->max_version;

  ssl->options = ctx->options;
  ssl->mode = ctx->mode;
  ssl->max_cert_list = ctx->max_cert_list;

  ssl->cert = ssl_cert_dup(ctx->cert);
  if (ssl->cert == NULL) {
    goto err;
  }

  ssl->msg_callback = ctx->msg_callback;
  ssl->msg_callback_arg = ctx->msg_callback_arg;
  ssl->verify_mode = ctx->verify_mode;
  ssl->sid_ctx_length = ctx->sid_ctx_length;
  assert(ssl->sid_ctx_length <= sizeof ssl->sid_ctx);
  memcpy(&ssl->sid_ctx, &ctx->sid_ctx, sizeof(ssl->sid_ctx));
  ssl->verify_callback = ctx->default_verify_callback;

  ssl->param = X509_VERIFY_PARAM_new();
  if (!ssl->param) {
    goto err;
  }
  X509_VERIFY_PARAM_inherit(ssl->param, ctx->param);
  ssl->quiet_shutdown = ctx->quiet_shutdown;
  ssl->max_send_fragment = ctx->max_send_fragment;

  CRYPTO_refcount_inc(&ctx->references);
  ssl->ctx = ctx;
  CRYPTO_refcount_inc(&ctx->references);
  ssl->initial_ctx = ctx;

  if (ctx->tlsext_ellipticcurvelist) {
    ssl->tlsext_ellipticcurvelist =
        BUF_memdup(ctx->tlsext_ellipticcurvelist,
                   ctx->tlsext_ellipticcurvelist_length * 2);
    if (!ssl->tlsext_ellipticcurvelist) {
      goto err;
    }
    ssl->tlsext_ellipticcurvelist_length = ctx->tlsext_ellipticcurvelist_length;
  }

  if (ssl->ctx->alpn_client_proto_list) {
    ssl->alpn_client_proto_list = BUF_memdup(
        ssl->ctx->alpn_client_proto_list, ssl->ctx->alpn_client_proto_list_len);
    if (ssl->alpn_client_proto_list == NULL) {
      goto err;
    }
    ssl->alpn_client_proto_list_len = ssl->ctx->alpn_client_proto_list_len;
  }

  ssl->verify_result = X509_V_OK;
  ssl->method = ctx->method;

  if (!ssl->method->ssl_new(ssl)) {
    goto err;
  }

  ssl->rwstate = SSL_NOTHING;

  CRYPTO_new_ex_data(&ssl->ex_data);

  ssl->psk_identity_hint = NULL;
  if (ctx->psk_identity_hint) {
    ssl->psk_identity_hint = BUF_strdup(ctx->psk_identity_hint);
    if (ssl->psk_identity_hint == NULL) {
      goto err;
    }
  }
  ssl->psk_client_callback = ctx->psk_client_callback;
  ssl->psk_server_callback = ctx->psk_server_callback;

  ssl->tlsext_channel_id_enabled = ctx->tlsext_channel_id_enabled;
  if (ctx->tlsext_channel_id_private) {
    ssl->tlsext_channel_id_private =
        EVP_PKEY_up_ref(ctx->tlsext_channel_id_private);
  }

  ssl->signed_cert_timestamps_enabled =
      ssl->ctx->signed_cert_timestamps_enabled;
  ssl->ocsp_stapling_enabled = ssl->ctx->ocsp_stapling_enabled;

  return ssl;

err:
  SSL_free(ssl);
  OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);

  return NULL;
}

void SSL_free(SSL *ssl) {
  if (ssl == NULL) {
    return;
  }

  X509_VERIFY_PARAM_free(ssl->param);

  CRYPTO_free_ex_data(&g_ex_data_class_ssl, ssl, &ssl->ex_data);

  if (ssl->bbio != NULL) {
    /* If the buffering BIO is in place, pop it off */
    if (ssl->bbio == ssl->wbio) {
      ssl->wbio = BIO_pop(ssl->wbio);
    }
    BIO_free(ssl->bbio);
    ssl->bbio = NULL;
  }

  int free_wbio = ssl->wbio != ssl->rbio;
  BIO_free_all(ssl->rbio);
  if (free_wbio) {
    BIO_free_all(ssl->wbio);
  }

  BUF_MEM_free(ssl->init_buf);

  /* add extra stuff */
  ssl_cipher_preference_list_free(ssl->cipher_list);
  sk_SSL_CIPHER_free(ssl->cipher_list_by_id);

  ssl_clear_bad_session(ssl);
  SSL_SESSION_free(ssl->session);

  ssl_cert_free(ssl->cert);

  OPENSSL_free(ssl->tlsext_hostname);
  SSL_CTX_free(ssl->initial_ctx);
  OPENSSL_free(ssl->tlsext_ellipticcurvelist);
  OPENSSL_free(ssl->alpn_client_proto_list);
  EVP_PKEY_free(ssl->tlsext_channel_id_private);
  OPENSSL_free(ssl->psk_identity_hint);
  sk_X509_NAME_pop_free(ssl->client_CA, X509_NAME_free);
  sk_SRTP_PROTECTION_PROFILE_free(ssl->srtp_profiles);

  if (ssl->method != NULL) {
    ssl->method->ssl_free(ssl);
  }
  SSL_CTX_free(ssl->ctx);

  OPENSSL_free(ssl);
}

void SSL_set_connect_state(SSL *ssl) {
  ssl->server = 0;
  ssl->shutdown = 0;
  ssl->state = SSL_ST_CONNECT;
  ssl->handshake_func = ssl->method->ssl_connect;
}

void SSL_set_accept_state(SSL *ssl) {
  ssl->server = 1;
  ssl->shutdown = 0;
  ssl->state = SSL_ST_ACCEPT;
  ssl->handshake_func = ssl->method->ssl_accept;
}

void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio) {
  /* If the output buffering BIO is still in place, remove it. */
  if (ssl->bbio != NULL) {
    if (ssl->wbio == ssl->bbio) {
      ssl->wbio = ssl->wbio->next_bio;
      ssl->bbio->next_bio = NULL;
    }
  }

  if (ssl->rbio != rbio) {
    BIO_free_all(ssl->rbio);
  }
  if (ssl->wbio != wbio && ssl->rbio != ssl->wbio) {
    BIO_free_all(ssl->wbio);
  }
  ssl->rbio = rbio;
  ssl->wbio = wbio;
}

BIO *SSL_get_rbio(const SSL *ssl) { return ssl->rbio; }

BIO *SSL_get_wbio(const SSL *ssl) { return ssl->wbio; }

int SSL_do_handshake(SSL *ssl) {
  ssl->rwstate = SSL_NOTHING;
  /* Functions which use SSL_get_error must clear the error queue on entry. */
  ERR_clear_error();

  if (ssl->handshake_func == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CONNECTION_TYPE_NOT_SET);
    return -1;
  }

  if (!SSL_in_init(ssl)) {
    return 1;
  }

  return ssl->handshake_func(ssl);
}

int SSL_connect(SSL *ssl) {
  if (ssl->handshake_func == NULL) {
    /* Not properly initialized yet */
    SSL_set_connect_state(ssl);
  }

  assert(ssl->handshake_func == ssl->method->ssl_connect);

  return SSL_do_handshake(ssl);
}

int SSL_accept(SSL *ssl) {
  if (ssl->handshake_func == NULL) {
    /* Not properly initialized yet */
    SSL_set_accept_state(ssl);
  }

  assert(ssl->handshake_func == ssl->method->ssl_accept);

  return SSL_do_handshake(ssl);
}

static int ssl_read_impl(SSL *ssl, void *buf, int num, int peek) {
  ssl->rwstate = SSL_NOTHING;
  /* Functions which use SSL_get_error must clear the error queue on entry. */
  ERR_clear_error();
  ERR_clear_system_error();

  if (ssl->handshake_func == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
    return -1;
  }

  if (ssl->shutdown & SSL_RECEIVED_SHUTDOWN) {
    return 0;
  }

  /* This may require multiple iterations. False Start will cause
   * |ssl->handshake_func| to signal success one step early, but the handshake
   * must be completely finished before other modes are accepted. */
  while (SSL_in_init(ssl)) {
    int ret = SSL_do_handshake(ssl);
    if (ret < 0) {
      return ret;
    }
    if (ret == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

  return ssl->method->ssl_read_app_data(ssl, buf, num, peek);
}

int SSL_read(SSL *ssl, void *buf, int num) {
  return ssl_read_impl(ssl, buf, num, 0 /* consume bytes */);
}

int SSL_peek(SSL *ssl, void *buf, int num) {
  return ssl_read_impl(ssl, buf, num, 1 /* peek */);
}

int SSL_write(SSL *ssl, const void *buf, int num) {
  ssl->rwstate = SSL_NOTHING;
  /* Functions which use SSL_get_error must clear the error queue on entry. */
  ERR_clear_error();
  ERR_clear_system_error();

  if (ssl->handshake_func == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
    return -1;
  }

  if (ssl->shutdown & SSL_SENT_SHUTDOWN) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_PROTOCOL_IS_SHUTDOWN);
    return -1;
  }

  /* If necessary, complete the handshake implicitly. */
  if (SSL_in_init(ssl) && !SSL_in_false_start(ssl)) {
    int ret = SSL_do_handshake(ssl);
    if (ret < 0) {
      return ret;
    }
    if (ret == 0) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_HANDSHAKE_FAILURE);
      return -1;
    }
  }

  return ssl->method->ssl_write_app_data(ssl, buf, num);
}

int SSL_shutdown(SSL *ssl) {
  ssl->rwstate = SSL_NOTHING;
  /* Functions which use SSL_get_error must clear the error queue on entry. */
  ERR_clear_error();

  /* Note that this function behaves differently from what one might expect.
   * Return values are 0 for no success (yet), 1 for success; but calling it
   * once is usually not enough, even if blocking I/O is used (see
   * ssl3_shutdown). */

  if (ssl->handshake_func == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_UNINITIALIZED);
    return -1;
  }

  /* We can't shutdown properly if we are in the middle of a handshake. */
  if (SSL_in_init(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SHUTDOWN_WHILE_IN_INIT);
    return -1;
  }

  /* Do nothing if configured not to send a close_notify. */
  if (ssl->quiet_shutdown) {
    ssl->shutdown = SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN;
    return 1;
  }

  if (!(ssl->shutdown & SSL_SENT_SHUTDOWN)) {
    ssl->shutdown |= SSL_SENT_SHUTDOWN;
    ssl3_send_alert(ssl, SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY);

    /* our shutdown alert has been sent now, and if it still needs to be
     * written, ssl->s3->alert_dispatch will be true */
    if (ssl->s3->alert_dispatch) {
      return -1; /* return WANT_WRITE */
    }
  } else if (ssl->s3->alert_dispatch) {
    /* resend it if not sent */
    int ret = ssl->method->ssl_dispatch_alert(ssl);
    if (ret == -1) {
      /* we only get to return -1 here the 2nd/Nth invocation, we must  have
       * already signalled return 0 upon a previous invoation, return
       * WANT_WRITE */
      return ret;
    }
  } else if (!(ssl->shutdown & SSL_RECEIVED_SHUTDOWN)) {
    /* If we are waiting for a close from our peer, we are closed */
    ssl->method->ssl_read_close_notify(ssl);
    if (!(ssl->shutdown & SSL_RECEIVED_SHUTDOWN)) {
      return -1; /* return WANT_READ */
    }
  }

  if (ssl->shutdown == (SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN) &&
      !ssl->s3->alert_dispatch) {
    return 1;
  } else {
    return 0;
  }
}

int SSL_get_error(const SSL *ssl, int ret_code) {
  int reason;
  uint32_t err;
  BIO *bio;

  if (ret_code > 0) {
    return SSL_ERROR_NONE;
  }

  /* Make things return SSL_ERROR_SYSCALL when doing SSL_do_handshake etc,
   * where we do encode the error */
  err = ERR_peek_error();
  if (err != 0) {
    if (ERR_GET_LIB(err) == ERR_LIB_SYS) {
      return SSL_ERROR_SYSCALL;
    }
    return SSL_ERROR_SSL;
  }

  if (ret_code == 0) {
    if ((ssl->shutdown & SSL_RECEIVED_SHUTDOWN) && ssl->s3->clean_shutdown) {
      /* The socket was cleanly shut down with a close_notify. */
      return SSL_ERROR_ZERO_RETURN;
    }
    /* An EOF was observed which violates the protocol, and the underlying
     * transport does not participate in the error queue. Bubble up to the
     * caller. */
    return SSL_ERROR_SYSCALL;
  }

  if (SSL_want_session(ssl)) {
    return SSL_ERROR_PENDING_SESSION;
  }

  if (SSL_want_certificate(ssl)) {
    return SSL_ERROR_PENDING_CERTIFICATE;
  }

  if (SSL_want_read(ssl)) {
    bio = SSL_get_rbio(ssl);
    if (BIO_should_read(bio)) {
      return SSL_ERROR_WANT_READ;
    }

    if (BIO_should_write(bio)) {
      /* This one doesn't make too much sense ... We never try to write to the
       * rbio, and an application program where rbio and wbio are separate
       * couldn't even know what it should wait for. However if we ever set
       * ssl->rwstate incorrectly (so that we have SSL_want_read(ssl) instead of
       * SSL_want_write(ssl)) and rbio and wbio *are* the same, this test works
       * around that bug; so it might be safer to keep it. */
      return SSL_ERROR_WANT_WRITE;
    }

    if (BIO_should_io_special(bio)) {
      reason = BIO_get_retry_reason(bio);
      if (reason == BIO_RR_CONNECT) {
        return SSL_ERROR_WANT_CONNECT;
      }

      if (reason == BIO_RR_ACCEPT) {
        return SSL_ERROR_WANT_ACCEPT;
      }

      return SSL_ERROR_SYSCALL; /* unknown */
    }
  }

  if (SSL_want_write(ssl)) {
    bio = SSL_get_wbio(ssl);
    if (BIO_should_write(bio)) {
      return SSL_ERROR_WANT_WRITE;
    }

    if (BIO_should_read(bio)) {
      /* See above (SSL_want_read(ssl) with BIO_should_write(bio)) */
      return SSL_ERROR_WANT_READ;
    }

    if (BIO_should_io_special(bio)) {
      reason = BIO_get_retry_reason(bio);
      if (reason == BIO_RR_CONNECT) {
        return SSL_ERROR_WANT_CONNECT;
      }

      if (reason == BIO_RR_ACCEPT) {
        return SSL_ERROR_WANT_ACCEPT;
      }

      return SSL_ERROR_SYSCALL;
    }
  }

  if (SSL_want_x509_lookup(ssl)) {
    return SSL_ERROR_WANT_X509_LOOKUP;
  }

  if (SSL_want_channel_id_lookup(ssl)) {
    return SSL_ERROR_WANT_CHANNEL_ID_LOOKUP;
  }

  if (SSL_want_private_key_operation(ssl)) {
    return SSL_ERROR_WANT_PRIVATE_KEY_OPERATION;
  }

  return SSL_ERROR_SYSCALL;
}

void SSL_CTX_set_min_version(SSL_CTX *ctx, uint16_t version) {
  ctx->min_version = version;
}

void SSL_CTX_set_max_version(SSL_CTX *ctx, uint16_t version) {
  ctx->max_version = version;
}

void SSL_set_min_version(SSL *ssl, uint16_t version) {
  ssl->min_version = version;
}

void SSL_set_max_version(SSL *ssl, uint16_t version) {
  ssl->max_version = version;
}

uint32_t SSL_CTX_set_options(SSL_CTX *ctx, uint32_t options) {
  ctx->options |= options;
  return ctx->options;
}

uint32_t SSL_CTX_clear_options(SSL_CTX *ctx, uint32_t options) {
  ctx->options &= ~options;
  return ctx->options;
}

uint32_t SSL_CTX_get_options(const SSL_CTX *ctx) { return ctx->options; }

uint32_t SSL_set_options(SSL *ssl, uint32_t options) {
  ssl->options |= options;
  return ssl->options;
}

uint32_t SSL_clear_options(SSL *ssl, uint32_t options) {
  ssl->options &= ~options;
  return ssl->options;
}

uint32_t SSL_get_options(const SSL *ssl) { return ssl->options; }

uint32_t SSL_CTX_set_mode(SSL_CTX *ctx, uint32_t mode) {
  ctx->mode |= mode;
  return ctx->mode;
}

uint32_t SSL_CTX_clear_mode(SSL_CTX *ctx, uint32_t mode) {
  ctx->mode &= ~mode;
  return ctx->mode;
}

uint32_t SSL_CTX_get_mode(const SSL_CTX *ctx) { return ctx->mode; }

uint32_t SSL_set_mode(SSL *ssl, uint32_t mode) {
  ssl->mode |= mode;
  return ssl->mode;
}

uint32_t SSL_clear_mode(SSL *ssl, uint32_t mode) {
  ssl->mode &= ~mode;
  return ssl->mode;
}

uint32_t SSL_get_mode(const SSL *ssl) { return ssl->mode; }

X509 *SSL_get_peer_certificate(const SSL *ssl) {
  if (ssl == NULL || ssl->session == NULL || ssl->session->peer == NULL) {
    return NULL;
  }
  return X509_up_ref(ssl->session->peer);
}

STACK_OF(X509) *SSL_get_peer_cert_chain(const SSL *ssl) {
  if (ssl == NULL || ssl->session == NULL) {
    return NULL;
  }
  return ssl->session->cert_chain;
}

int SSL_get_tls_unique(const SSL *ssl, uint8_t *out, size_t *out_len,
                       size_t max_out) {
  /* The tls-unique value is the first Finished message in the handshake, which
   * is the client's in a full handshake and the server's for a resumption. See
   * https://tools.ietf.org/html/rfc5929#section-3.1. */
  const uint8_t *finished = ssl->s3->previous_client_finished;
  size_t finished_len = ssl->s3->previous_client_finished_len;
  if (ssl->hit) {
    /* tls-unique is broken for resumed sessions unless EMS is used. */
    if (!ssl->session->extended_master_secret) {
      goto err;
    }
    finished = ssl->s3->previous_server_finished;
    finished_len = ssl->s3->previous_server_finished_len;
  }

  if (!ssl->s3->initial_handshake_complete ||
      ssl->version < TLS1_VERSION) {
    goto err;
  }

  *out_len = finished_len;
  if (finished_len > max_out) {
    *out_len = max_out;
  }

  memcpy(out, finished, *out_len);
  return 1;

err:
  *out_len = 0;
  memset(out, 0, max_out);
  return 0;
}

int SSL_CTX_set_session_id_context(SSL_CTX *ctx, const uint8_t *sid_ctx,
                                   unsigned sid_ctx_len) {
  if (sid_ctx_len > sizeof(ctx->sid_ctx)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }
  ctx->sid_ctx_length = sid_ctx_len;
  memcpy(ctx->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

int SSL_set_session_id_context(SSL *ssl, const uint8_t *sid_ctx,
                               unsigned sid_ctx_len) {
  if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }
  ssl->sid_ctx_length = sid_ctx_len;
  memcpy(ssl->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

int SSL_CTX_set_purpose(SSL_CTX *ctx, int purpose) {
  return X509_VERIFY_PARAM_set_purpose(ctx->param, purpose);
}

int SSL_set_purpose(SSL *ssl, int purpose) {
  return X509_VERIFY_PARAM_set_purpose(ssl->param, purpose);
}

int SSL_CTX_set_trust(SSL_CTX *ctx, int trust) {
  return X509_VERIFY_PARAM_set_trust(ctx->param, trust);
}

int SSL_set_trust(SSL *ssl, int trust) {
  return X509_VERIFY_PARAM_set_trust(ssl->param, trust);
}

int SSL_CTX_set1_param(SSL_CTX *ctx, const X509_VERIFY_PARAM *param) {
  return X509_VERIFY_PARAM_set1(ctx->param, param);
}

int SSL_set1_param(SSL *ssl, const X509_VERIFY_PARAM *param) {
  return X509_VERIFY_PARAM_set1(ssl->param, param);
}

void ssl_cipher_preference_list_free(
    struct ssl_cipher_preference_list_st *cipher_list) {
  if (cipher_list == NULL) {
    return;
  }
  sk_SSL_CIPHER_free(cipher_list->ciphers);
  OPENSSL_free(cipher_list->in_group_flags);
  OPENSSL_free(cipher_list);
}

X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *ctx) { return ctx->param; }

X509_VERIFY_PARAM *SSL_get0_param(SSL *ssl) { return ssl->param; }

void SSL_certs_clear(SSL *ssl) { ssl_cert_clear_certs(ssl->cert); }

int SSL_get_fd(const SSL *ssl) { return SSL_get_rfd(ssl); }

int SSL_get_rfd(const SSL *ssl) {
  int ret = -1;
  BIO *b = BIO_find_type(SSL_get_rbio(ssl), BIO_TYPE_DESCRIPTOR);
  if (b != NULL) {
    BIO_get_fd(b, &ret);
  }
  return ret;
}

int SSL_get_wfd(const SSL *ssl) {
  int ret = -1;
  BIO *b = BIO_find_type(SSL_get_wbio(ssl), BIO_TYPE_DESCRIPTOR);
  if (b != NULL) {
    BIO_get_fd(b, &ret);
  }
  return ret;
}

int SSL_set_fd(SSL *ssl, int fd) {
  BIO *bio = BIO_new(BIO_s_socket());
  if (bio == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
    return 0;
  }
  BIO_set_fd(bio, fd, BIO_NOCLOSE);
  SSL_set_bio(ssl, bio, bio);
  return 1;
}

int SSL_set_wfd(SSL *ssl, int fd) {
  if (ssl->rbio == NULL ||
      BIO_method_type(ssl->rbio) != BIO_TYPE_SOCKET ||
      BIO_get_fd(ssl->rbio, NULL) != fd) {
    BIO *bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
      return 0;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, SSL_get_rbio(ssl), bio);
  } else {
    SSL_set_bio(ssl, SSL_get_rbio(ssl), SSL_get_rbio(ssl));
  }

  return 1;
}

int SSL_set_rfd(SSL *ssl, int fd) {
  if (ssl->wbio == NULL || BIO_method_type(ssl->wbio) != BIO_TYPE_SOCKET ||
      BIO_get_fd(ssl->wbio, NULL) != fd) {
    BIO *bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
      return 0;
    }
    BIO_set_fd(bio, fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, SSL_get_wbio(ssl));
  } else {
    SSL_set_bio(ssl, SSL_get_wbio(ssl), SSL_get_wbio(ssl));
  }
  return 1;
}

size_t SSL_get_finished(const SSL *ssl, void *buf, size_t count) {
  size_t ret = 0;

  if (ssl->s3 != NULL) {
    ret = ssl->s3->tmp.finish_md_len;
    if (count > ret) {
      count = ret;
    }
    memcpy(buf, ssl->s3->tmp.finish_md, count);
  }

  return ret;
}

size_t SSL_get_peer_finished(const SSL *ssl, void *buf, size_t count) {
  size_t ret = 0;

  if (ssl->s3 != NULL) {
    ret = ssl->s3->tmp.peer_finish_md_len;
    if (count > ret) {
      count = ret;
    }
    memcpy(buf, ssl->s3->tmp.peer_finish_md, count);
  }

  return ret;
}

int SSL_get_verify_mode(const SSL *ssl) { return ssl->verify_mode; }

int SSL_get_verify_depth(const SSL *ssl) {
  return X509_VERIFY_PARAM_get_depth(ssl->param);
}

int SSL_get_extms_support(const SSL *ssl) {
  return ssl->s3->tmp.extended_master_secret == 1;
}

int (*SSL_get_verify_callback(const SSL *ssl))(int, X509_STORE_CTX *) {
  return ssl->verify_callback;
}

int SSL_CTX_get_verify_mode(const SSL_CTX *ctx) { return ctx->verify_mode; }

int SSL_CTX_get_verify_depth(const SSL_CTX *ctx) {
  return X509_VERIFY_PARAM_get_depth(ctx->param);
}

int (*SSL_CTX_get_verify_callback(const SSL_CTX *ctx))(
    int ok, X509_STORE_CTX *store_ctx) {
  return ctx->default_verify_callback;
}

void SSL_set_verify(SSL *ssl, int mode,
                    int (*callback)(int ok, X509_STORE_CTX *store_ctx)) {
  ssl->verify_mode = mode;
  if (callback != NULL) {
    ssl->verify_callback = callback;
  }
}

void SSL_set_verify_depth(SSL *ssl, int depth) {
  X509_VERIFY_PARAM_set_depth(ssl->param, depth);
}

int SSL_CTX_get_read_ahead(const SSL_CTX *ctx) { return 0; }

int SSL_get_read_ahead(const SSL *ssl) { return 0; }

void SSL_CTX_set_read_ahead(SSL_CTX *ctx, int yes) { }

void SSL_set_read_ahead(SSL *ssl, int yes) { }

int SSL_pending(const SSL *ssl) {
  if (ssl->s3->rrec.type != SSL3_RT_APPLICATION_DATA) {
    return 0;
  }
  return ssl->s3->rrec.length;
}

/* Fix this so it checks all the valid key/cert options */
int SSL_CTX_check_private_key(const SSL_CTX *ctx) {
  if (ctx->cert->x509 == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_ASSIGNED);
    return 0;
  }

  if (ctx->cert->privatekey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
    return 0;
  }

  return X509_check_private_key(ctx->cert->x509, ctx->cert->privatekey);
}

/* Fix this function so that it takes an optional type parameter */
int SSL_check_private_key(const SSL *ssl) {
  if (ssl->cert->x509 == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CERTIFICATE_ASSIGNED);
    return 0;
  }

  if (ssl->cert->privatekey == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_PRIVATE_KEY_ASSIGNED);
    return 0;
  }

  return X509_check_private_key(ssl->cert->x509, ssl->cert->privatekey);
}

long SSL_get_default_timeout(const SSL *ssl) {
  return SSL_DEFAULT_SESSION_TIMEOUT;
}

int SSL_renegotiate(SSL *ssl) {
  /* Caller-initiated renegotiation is not supported. */
  OPENSSL_PUT_ERROR(SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
  return 0;
}

int SSL_renegotiate_pending(SSL *ssl) {
  return SSL_in_init(ssl) && ssl->s3->initial_handshake_complete;
}

size_t SSL_CTX_get_max_cert_list(const SSL_CTX *ctx) {
  return ctx->max_cert_list;
}

void SSL_CTX_set_max_cert_list(SSL_CTX *ctx, size_t max_cert_list) {
  if (max_cert_list > kMaxHandshakeSize) {
    max_cert_list = kMaxHandshakeSize;
  }
  ctx->max_cert_list = (uint32_t)max_cert_list;
}

size_t SSL_get_max_cert_list(const SSL *ssl) {
  return ssl->max_cert_list;
}

void SSL_set_max_cert_list(SSL *ssl, size_t max_cert_list) {
  if (max_cert_list > kMaxHandshakeSize) {
    max_cert_list = kMaxHandshakeSize;
  }
  ssl->max_cert_list = (uint32_t)max_cert_list;
}

int SSL_CTX_set_max_send_fragment(SSL_CTX *ctx, size_t max_send_fragment) {
  if (max_send_fragment < 512) {
    max_send_fragment = 512;
  }
  if (max_send_fragment > SSL3_RT_MAX_PLAIN_LENGTH) {
    max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;
  }
  ctx->max_send_fragment = (uint16_t)max_send_fragment;

  return 1;
}

int SSL_set_max_send_fragment(SSL *ssl, size_t max_send_fragment) {
  if (max_send_fragment < 512) {
    max_send_fragment = 512;
  }
  if (max_send_fragment > SSL3_RT_MAX_PLAIN_LENGTH) {
    max_send_fragment = SSL3_RT_MAX_PLAIN_LENGTH;
  }
  ssl->max_send_fragment = (uint16_t)max_send_fragment;

  return 1;
}

int SSL_set_mtu(SSL *ssl, unsigned mtu) {
  if (!SSL_IS_DTLS(ssl) || mtu < dtls1_min_mtu()) {
    return 0;
  }
  ssl->d1->mtu = mtu;
  return 1;
}

int SSL_get_secure_renegotiation_support(const SSL *ssl) {
  return ssl->s3->send_connection_binding;
}

LHASH_OF(SSL_SESSION) *SSL_CTX_sessions(SSL_CTX *ctx) { return ctx->sessions; }

size_t SSL_CTX_sess_number(const SSL_CTX *ctx) {
  return lh_SSL_SESSION_num_items(ctx->sessions);
}

unsigned long SSL_CTX_sess_set_cache_size(SSL_CTX *ctx, unsigned long size) {
  unsigned long ret = ctx->session_cache_size;
  ctx->session_cache_size = size;
  return ret;
}

unsigned long SSL_CTX_sess_get_cache_size(const SSL_CTX *ctx) {
  return ctx->session_cache_size;
}

int SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, int mode) {
  int ret = ctx->session_cache_mode;
  ctx->session_cache_mode = mode;
  return ret;
}

int SSL_CTX_get_session_cache_mode(const SSL_CTX *ctx) {
  return ctx->session_cache_mode;
}

STACK_OF(SSL_CIPHER) *SSL_get_ciphers(const SSL *ssl) {
  if (ssl == NULL) {
    return NULL;
  }

  if (ssl->cipher_list != NULL) {
    return ssl->cipher_list->ciphers;
  }

  if (ssl->version >= TLS1_1_VERSION && ssl->ctx->cipher_list_tls11 != NULL) {
    return ssl->ctx->cipher_list_tls11->ciphers;
  }

  if (ssl->version >= TLS1_VERSION && ssl->ctx->cipher_list_tls10 != NULL) {
    return ssl->ctx->cipher_list_tls10->ciphers;
  }

  if (ssl->ctx->cipher_list != NULL) {
    return ssl->ctx->cipher_list->ciphers;
  }

  return NULL;
}

/* return a STACK of the ciphers available for the SSL and in order of
 * algorithm id */
STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *ssl) {
  if (ssl == NULL) {
    return NULL;
  }

  if (ssl->cipher_list_by_id != NULL) {
    return ssl->cipher_list_by_id;
  }

  if (ssl->ctx->cipher_list_by_id != NULL) {
    return ssl->ctx->cipher_list_by_id;
  }

  return NULL;
}

const char *SSL_get_cipher_list(const SSL *ssl, int n) {
  const SSL_CIPHER *c;
  STACK_OF(SSL_CIPHER) *sk;

  if (ssl == NULL) {
    return NULL;
  }

  sk = SSL_get_ciphers(ssl);
  if (sk == NULL || n < 0 || (size_t)n >= sk_SSL_CIPHER_num(sk)) {
    return NULL;
  }

  c = sk_SSL_CIPHER_value(sk, n);
  if (c == NULL) {
    return NULL;
  }

  return c->name;
}

int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str) {
  STACK_OF(SSL_CIPHER) *cipher_list = ssl_create_cipher_list(
      ctx->method, &ctx->cipher_list, &ctx->cipher_list_by_id, str);
  if (cipher_list == NULL) {
    return 0;
  }

  /* |ssl_create_cipher_list| may succeed but return an empty cipher list. */
  if (sk_SSL_CIPHER_num(cipher_list) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHER_MATCH);
    return 0;
  }

  return 1;
}

int SSL_CTX_set_cipher_list_tls10(SSL_CTX *ctx, const char *str) {
  STACK_OF(SSL_CIPHER) *cipher_list = ssl_create_cipher_list(
      ctx->method, &ctx->cipher_list_tls10, NULL, str);
  if (cipher_list == NULL) {
    return 0;
  }

  /* |ssl_create_cipher_list| may succeed but return an empty cipher list. */
  if (sk_SSL_CIPHER_num(cipher_list) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHER_MATCH);
    return 0;
  }

  return 1;
}

int SSL_CTX_set_cipher_list_tls11(SSL_CTX *ctx, const char *str) {
  STACK_OF(SSL_CIPHER) *cipher_list = ssl_create_cipher_list(
      ctx->method, &ctx->cipher_list_tls11, NULL, str);
  if (cipher_list == NULL) {
    return 0;
  }

  /* |ssl_create_cipher_list| may succeed but return an empty cipher list. */
  if (sk_SSL_CIPHER_num(cipher_list) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHER_MATCH);
    return 0;
  }

  return 1;
}

int SSL_set_cipher_list(SSL *ssl, const char *str) {
  STACK_OF(SSL_CIPHER) *cipher_list = ssl_create_cipher_list(
      ssl->ctx->method, &ssl->cipher_list, &ssl->cipher_list_by_id, str);
  if (cipher_list == NULL) {
    return 0;
  }

  /* |ssl_create_cipher_list| may succeed but return an empty cipher list. */
  if (sk_SSL_CIPHER_num(cipher_list) == 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_CIPHER_MATCH);
    return 0;
  }

  return 1;
}

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *ssl, const CBS *cbs) {
  CBS cipher_suites = *cbs;
  const SSL_CIPHER *c;
  STACK_OF(SSL_CIPHER) *sk;

  if (ssl->s3) {
    ssl->s3->send_connection_binding = 0;
  }

  if (CBS_len(&cipher_suites) % 2 != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_ERROR_IN_RECEIVED_CIPHER_LIST);
    return NULL;
  }

  sk = sk_SSL_CIPHER_new_null();
  if (sk == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  while (CBS_len(&cipher_suites) > 0) {
    uint16_t cipher_suite;

    if (!CBS_get_u16(&cipher_suites, &cipher_suite)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
      goto err;
    }

    /* Check for SCSV. */
    if (ssl->s3 && cipher_suite == (SSL3_CK_SCSV & 0xffff)) {
      /* SCSV is fatal if renegotiating. */
      if (ssl->s3->initial_handshake_complete) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_SCSV_RECEIVED_WHEN_RENEGOTIATING);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE);
        goto err;
      }
      ssl->s3->send_connection_binding = 1;
      continue;
    }

    /* Check for FALLBACK_SCSV. */
    if (ssl->s3 && cipher_suite == (SSL3_CK_FALLBACK_SCSV & 0xffff)) {
      uint16_t max_version = ssl3_get_max_server_version(ssl);
      if (SSL_IS_DTLS(ssl) ? (uint16_t)ssl->version > max_version
                         : (uint16_t)ssl->version < max_version) {
        OPENSSL_PUT_ERROR(SSL, SSL_R_INAPPROPRIATE_FALLBACK);
        ssl3_send_alert(ssl, SSL3_AL_FATAL, SSL3_AD_INAPPROPRIATE_FALLBACK);
        goto err;
      }
      continue;
    }

    c = SSL_get_cipher_by_value(cipher_suite);
    if (c != NULL && !sk_SSL_CIPHER_push(sk, c)) {
      OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  return sk;

err:
  sk_SSL_CIPHER_free(sk);
  return NULL;
}

const char *SSL_get_servername(const SSL *ssl, const int type) {
  if (type != TLSEXT_NAMETYPE_host_name) {
    return NULL;
  }

  /* Historically, |SSL_get_servername| was also the configuration getter
   * corresponding to |SSL_set_tlsext_host_name|. */
  if (ssl->tlsext_hostname != NULL) {
    return ssl->tlsext_hostname;
  }

  if (ssl->session == NULL) {
    return NULL;
  }
  return ssl->session->tlsext_hostname;
}

int SSL_get_servername_type(const SSL *ssl) {
  if (ssl->session != NULL && ssl->session->tlsext_hostname != NULL) {
    return TLSEXT_NAMETYPE_host_name;
  }

  return -1;
}

void SSL_CTX_enable_signed_cert_timestamps(SSL_CTX *ctx) {
  ctx->signed_cert_timestamps_enabled = 1;
}

int SSL_enable_signed_cert_timestamps(SSL *ssl) {
  ssl->signed_cert_timestamps_enabled = 1;
  return 1;
}

void SSL_CTX_enable_ocsp_stapling(SSL_CTX *ctx) {
  ctx->ocsp_stapling_enabled = 1;
}

int SSL_enable_ocsp_stapling(SSL *ssl) {
  ssl->ocsp_stapling_enabled = 1;
  return 1;
}

void SSL_get0_signed_cert_timestamp_list(const SSL *ssl, const uint8_t **out,
                                         size_t *out_len) {
  SSL_SESSION *session = ssl->session;

  *out_len = 0;
  *out = NULL;
  if (ssl->server || !session || !session->tlsext_signed_cert_timestamp_list) {
    return;
  }

  *out = session->tlsext_signed_cert_timestamp_list;
  *out_len = session->tlsext_signed_cert_timestamp_list_length;
}

void SSL_get0_ocsp_response(const SSL *ssl, const uint8_t **out,
                            size_t *out_len) {
  SSL_SESSION *session = ssl->session;

  *out_len = 0;
  *out = NULL;
  if (ssl->server || !session || !session->ocsp_response) {
    return;
  }
  *out = session->ocsp_response;
  *out_len = session->ocsp_response_length;
}

int SSL_CTX_set_signed_cert_timestamp_list(SSL_CTX *ctx, const uint8_t *list,
                                           size_t list_len) {
  OPENSSL_free(ctx->signed_cert_timestamp_list);
  ctx->signed_cert_timestamp_list_length = 0;

  ctx->signed_cert_timestamp_list = BUF_memdup(list, list_len);
  if (ctx->signed_cert_timestamp_list == NULL) {
    return 0;
  }
  ctx->signed_cert_timestamp_list_length = list_len;

  return 1;
}

int SSL_CTX_set_ocsp_response(SSL_CTX *ctx, const uint8_t *response,
                              size_t response_len) {
  OPENSSL_free(ctx->ocsp_response);
  ctx->ocsp_response_length = 0;

  ctx->ocsp_response = BUF_memdup(response, response_len);
  if (ctx->ocsp_response == NULL) {
    return 0;
  }
  ctx->ocsp_response_length = response_len;

  return 1;
}

int SSL_select_next_proto(uint8_t **out, uint8_t *out_len,
                          const uint8_t *server, unsigned server_len,
                          const uint8_t *client, unsigned client_len) {
  unsigned int i, j;
  const uint8_t *result;
  int status = OPENSSL_NPN_UNSUPPORTED;

  /* For each protocol in server preference order, see if we support it. */
  for (i = 0; i < server_len;) {
    for (j = 0; j < client_len;) {
      if (server[i] == client[j] &&
          memcmp(&server[i + 1], &client[j + 1], server[i]) == 0) {
        /* We found a match */
        result = &server[i];
        status = OPENSSL_NPN_NEGOTIATED;
        goto found;
      }
      j += client[j];
      j++;
    }
    i += server[i];
    i++;
  }

  /* There's no overlap between our protocols and the server's list. */
  result = client;
  status = OPENSSL_NPN_NO_OVERLAP;

found:
  *out = (uint8_t *)result + 1;
  *out_len = result[0];
  return status;
}

void SSL_get0_next_proto_negotiated(const SSL *ssl, const uint8_t **out_data,
                                    unsigned *out_len) {
  *out_data = ssl->s3->next_proto_negotiated;
  if (*out_data == NULL) {
    *out_len = 0;
  } else {
    *out_len = ssl->s3->next_proto_negotiated_len;
  }
}

void SSL_CTX_set_next_protos_advertised_cb(
    SSL_CTX *ctx,
    int (*cb)(SSL *ssl, const uint8_t **out, unsigned *out_len, void *arg),
    void *arg) {
  ctx->next_protos_advertised_cb = cb;
  ctx->next_protos_advertised_cb_arg = arg;
}

void SSL_CTX_set_next_proto_select_cb(
    SSL_CTX *ctx, int (*cb)(SSL *ssl, uint8_t **out, uint8_t *out_len,
                            const uint8_t *in, unsigned in_len, void *arg),
    void *arg) {
  ctx->next_proto_select_cb = cb;
  ctx->next_proto_select_cb_arg = arg;
}

int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const uint8_t *protos,
                            unsigned protos_len) {
  OPENSSL_free(ctx->alpn_client_proto_list);
  ctx->alpn_client_proto_list = BUF_memdup(protos, protos_len);
  if (!ctx->alpn_client_proto_list) {
    return 1;
  }
  ctx->alpn_client_proto_list_len = protos_len;

  return 0;
}

int SSL_set_alpn_protos(SSL *ssl, const uint8_t *protos, unsigned protos_len) {
  OPENSSL_free(ssl->alpn_client_proto_list);
  ssl->alpn_client_proto_list = BUF_memdup(protos, protos_len);
  if (!ssl->alpn_client_proto_list) {
    return 1;
  }
  ssl->alpn_client_proto_list_len = protos_len;

  return 0;
}

void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                int (*cb)(SSL *ssl, const uint8_t **out,
                                          uint8_t *out_len, const uint8_t *in,
                                          unsigned in_len, void *arg),
                                void *arg) {
  ctx->alpn_select_cb = cb;
  ctx->alpn_select_cb_arg = arg;
}

void SSL_get0_alpn_selected(const SSL *ssl, const uint8_t **out_data,
                            unsigned *out_len) {
  *out_data = NULL;
  if (ssl->s3) {
    *out_data = ssl->s3->alpn_selected;
  }
  if (*out_data == NULL) {
    *out_len = 0;
  } else {
    *out_len = ssl->s3->alpn_selected_len;
  }
}

void SSL_CTX_set_cert_verify_callback(SSL_CTX *ctx,
                                      int (*cb)(X509_STORE_CTX *store_ctx,
                                                void *arg),
                                      void *arg) {
  ctx->app_verify_callback = cb;
  ctx->app_verify_arg = arg;
}

void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
                        int (*cb)(int, X509_STORE_CTX *)) {
  ctx->verify_mode = mode;
  ctx->default_verify_callback = cb;
}

void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth) {
  X509_VERIFY_PARAM_set_depth(ctx->param, depth);
}

void SSL_CTX_set_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl, void *arg),
                         void *arg) {
  ssl_cert_set_cert_cb(ctx->cert, cb, arg);
}

void SSL_set_cert_cb(SSL *ssl, int (*cb)(SSL *ssl, void *arg), void *arg) {
  ssl_cert_set_cert_cb(ssl->cert, cb, arg);
}

void ssl_get_compatible_server_ciphers(SSL *ssl, uint32_t *out_mask_k,
                                       uint32_t *out_mask_a) {
  CERT *c = ssl->cert;
  int have_rsa_cert = 0, dh_tmp;
  uint32_t mask_k, mask_a;
  int have_ecc_cert = 0, ecdsa_ok;
  X509 *x;

  dh_tmp = (c->dh_tmp != NULL || c->dh_tmp_cb != NULL);

  if (ssl->cert->x509 != NULL && ssl_has_private_key(ssl)) {
    if (ssl_private_key_type(ssl) == EVP_PKEY_RSA) {
      have_rsa_cert = 1;
    } else if (ssl_private_key_type(ssl) == EVP_PKEY_EC) {
      have_ecc_cert = 1;
    }
  }

  mask_k = 0;
  mask_a = 0;

  if (dh_tmp) {
    mask_k |= SSL_kDHE;
  }
  if (have_rsa_cert) {
    mask_k |= SSL_kRSA;
    mask_a |= SSL_aRSA;
  }

  /* An ECC certificate may be usable for ECDSA cipher suites depending on the
   * key usage extension and on the client's curve preferences. */
  if (have_ecc_cert) {
    x = c->x509;
    /* This call populates extension flags (ex_flags). */
    X509_check_purpose(x, -1, 0);
    ecdsa_ok = (x->ex_flags & EXFLAG_KUSAGE)
                   ? (x->ex_kusage & X509v3_KU_DIGITAL_SIGNATURE)
                   : 1;
    if (!tls1_check_ec_cert(ssl, x)) {
      ecdsa_ok = 0;
    }
    if (ecdsa_ok) {
      mask_a |= SSL_aECDSA;
    }
  }

  /* If we are considering an ECC cipher suite that uses an ephemeral EC
   * key, check for a shared curve. */
  uint16_t unused;
  if (tls1_get_shared_curve(ssl, &unused)) {
    mask_k |= SSL_kECDHE;
  }

  /* PSK requires a server callback. */
  if (ssl->psk_server_callback != NULL) {
    mask_k |= SSL_kPSK;
    mask_a |= SSL_aPSK;
  }

  *out_mask_k = mask_k;
  *out_mask_a = mask_a;
}

void ssl_update_cache(SSL *ssl, int mode) {
  SSL_CTX *ctx = ssl->initial_ctx;
  /* Never cache sessions with empty session IDs. */
  if (ssl->session->session_id_length == 0 ||
      (ctx->session_cache_mode & mode) != mode) {
    return;
  }

  /* Clients never use the internal session cache. */
  int use_internal_cache = ssl->server && !(ctx->session_cache_mode &
                                            SSL_SESS_CACHE_NO_INTERNAL_STORE);

  /* A client may see new sessions on abbreviated handshakes if the server
   * decides to renew the ticket. Once the handshake is completed, it should be
   * inserted into the cache. */
  if (!ssl->hit || (!ssl->server && ssl->tlsext_ticket_expected)) {
    if (use_internal_cache) {
      SSL_CTX_add_session(ctx, ssl->session);
    }
    if (ctx->new_session_cb != NULL &&
        !ctx->new_session_cb(ssl, SSL_SESSION_up_ref(ssl->session))) {
      /* |new_session_cb|'s return value signals whether it took ownership. */
      SSL_SESSION_free(ssl->session);
    }
  }

  if (use_internal_cache &&
      !(ctx->session_cache_mode & SSL_SESS_CACHE_NO_AUTO_CLEAR)) {
    /* Automatically flush the internal session cache every 255 connections. */
    int flush_cache = 0;
    CRYPTO_MUTEX_lock_write(&ctx->lock);
    ctx->handshakes_since_cache_flush++;
    if (ctx->handshakes_since_cache_flush >= 255) {
      flush_cache = 1;
      ctx->handshakes_since_cache_flush = 0;
    }
    CRYPTO_MUTEX_unlock(&ctx->lock);

    if (flush_cache) {
      SSL_CTX_flush_sessions(ctx, (unsigned long)time(NULL));
    }
  }
}

static const char *ssl_get_version(int version) {
  switch (version) {
    case TLS1_2_VERSION:
      return "TLSv1.2";

    case TLS1_1_VERSION:
      return "TLSv1.1";

    case TLS1_VERSION:
      return "TLSv1";

    case SSL3_VERSION:
      return "SSLv3";

    case DTLS1_VERSION:
      return "DTLSv1";

    case DTLS1_2_VERSION:
      return "DTLSv1.2";

    default:
      return "unknown";
  }
}

const char *SSL_get_version(const SSL *ssl) {
  return ssl_get_version(ssl->version);
}

const char *SSL_SESSION_get_version(const SSL_SESSION *session) {
  return ssl_get_version(session->ssl_version);
}

X509 *SSL_get_certificate(const SSL *ssl) {
  if (ssl->cert != NULL) {
    return ssl->cert->x509;
  }

  return NULL;
}

EVP_PKEY *SSL_get_privatekey(const SSL *ssl) {
  if (ssl->cert != NULL) {
    return ssl->cert->privatekey;
  }

  return NULL;
}

X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx) {
  if (ctx->cert != NULL) {
    return ctx->cert->x509;
  }

  return NULL;
}

EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx) {
  if (ctx->cert != NULL) {
    return ctx->cert->privatekey;
  }

  return NULL;
}

const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl) {
  if (ssl->s3->aead_write_ctx == NULL) {
    return NULL;
  }
  return ssl->s3->aead_write_ctx->cipher;
}

const COMP_METHOD *SSL_get_current_compression(SSL *ssl) { return NULL; }

const COMP_METHOD *SSL_get_current_expansion(SSL *ssl) { return NULL; }

int *SSL_get_server_tmp_key(SSL *ssl, EVP_PKEY **out_key) { return 0; }

int ssl_init_wbio_buffer(SSL *ssl, int push) {
  BIO *bbio;

  if (ssl->bbio == NULL) {
    bbio = BIO_new(BIO_f_buffer());
    if (bbio == NULL) {
      return 0;
    }
    ssl->bbio = bbio;
  } else {
    bbio = ssl->bbio;
    if (ssl->bbio == ssl->wbio) {
      ssl->wbio = BIO_pop(ssl->wbio);
    }
  }

  BIO_reset(bbio);
  if (!BIO_set_read_buffer_size(bbio, 1)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
    return 0;
  }

  if (push) {
    if (ssl->wbio != bbio) {
      ssl->wbio = BIO_push(bbio, ssl->wbio);
    }
  } else {
    if (ssl->wbio == bbio) {
      ssl->wbio = BIO_pop(bbio);
    }
  }

  return 1;
}

void ssl_free_wbio_buffer(SSL *ssl) {
  if (ssl->bbio == NULL) {
    return;
  }

  if (ssl->bbio == ssl->wbio) {
    /* remove buffering */
    ssl->wbio = BIO_pop(ssl->wbio);
  }

  BIO_free(ssl->bbio);
  ssl->bbio = NULL;
}

void SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode) {
  ctx->quiet_shutdown = (mode != 0);
}

int SSL_CTX_get_quiet_shutdown(const SSL_CTX *ctx) {
  return ctx->quiet_shutdown;
}

void SSL_set_quiet_shutdown(SSL *ssl, int mode) {
  ssl->quiet_shutdown = (mode != 0);
}

int SSL_get_quiet_shutdown(const SSL *ssl) { return ssl->quiet_shutdown; }

void SSL_set_shutdown(SSL *ssl, int mode) {
  /* It is an error to clear any bits that have already been set. (We can't try
   * to get a second close_notify or send two.) */
  assert((ssl->shutdown & mode) == ssl->shutdown);

  ssl->shutdown |= mode;
}

int SSL_get_shutdown(const SSL *ssl) { return ssl->shutdown; }

int SSL_version(const SSL *ssl) { return ssl->version; }

SSL_CTX *SSL_get_SSL_CTX(const SSL *ssl) { return ssl->ctx; }

SSL_CTX *SSL_set_SSL_CTX(SSL *ssl, SSL_CTX *ctx) {
  if (ssl->ctx == ctx) {
    return ssl->ctx;
  }

  if (ctx == NULL) {
    ctx = ssl->initial_ctx;
  }

  ssl_cert_free(ssl->cert);
  ssl->cert = ssl_cert_dup(ctx->cert);

  CRYPTO_refcount_inc(&ctx->references);
  SSL_CTX_free(ssl->ctx); /* decrement reference count */
  ssl->ctx = ctx;

  ssl->sid_ctx_length = ctx->sid_ctx_length;
  assert(ssl->sid_ctx_length <= sizeof(ssl->sid_ctx));
  memcpy(ssl->sid_ctx, ctx->sid_ctx, sizeof(ssl->sid_ctx));

  return ssl->ctx;
}

int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx) {
  return X509_STORE_set_default_paths(ctx->cert_store);
}

int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *ca_file,
                                  const char *ca_dir) {
  return X509_STORE_load_locations(ctx->cert_store, ca_file, ca_dir);
}

void SSL_set_info_callback(SSL *ssl,
                           void (*cb)(const SSL *ssl, int type, int value)) {
  ssl->info_callback = cb;
}

void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl, int type,
                                              int value) {
  return ssl->info_callback;
}

int SSL_state(const SSL *ssl) { return ssl->state; }

void SSL_set_state(SSL *ssl, int state) { }

char *SSL_get_shared_ciphers(const SSL *ssl, char *buf, int len) {
  if (len <= 0) {
    return NULL;
  }
  buf[0] = '\0';
  return buf;
}

void SSL_set_verify_result(SSL *ssl, long result) {
  ssl->verify_result = result;
}

long SSL_get_verify_result(const SSL *ssl) { return ssl->verify_result; }

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
                         CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class_ssl, &index, argl, argp,
                               dup_func, free_func)) {
    return -1;
  }
  return index;
}

int SSL_set_ex_data(SSL *ssl, int idx, void *arg) {
  return CRYPTO_set_ex_data(&ssl->ex_data, idx, arg);
}

void *SSL_get_ex_data(const SSL *ssl, int idx) {
  return CRYPTO_get_ex_data(&ssl->ex_data, idx);
}

int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_unused *unused,
                             CRYPTO_EX_dup *dup_func,
                             CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class_ssl_ctx, &index, argl, argp,
                               dup_func, free_func)) {
    return -1;
  }
  return index;
}

int SSL_CTX_set_ex_data(SSL_CTX *ctx, int idx, void *arg) {
  return CRYPTO_set_ex_data(&ctx->ex_data, idx, arg);
}

void *SSL_CTX_get_ex_data(const SSL_CTX *ctx, int idx) {
  return CRYPTO_get_ex_data(&ctx->ex_data, idx);
}

X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx) {
  return ctx->cert_store;
}

void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store) {
  X509_STORE_free(ctx->cert_store);
  ctx->cert_store = store;
}

int SSL_want(const SSL *ssl) { return ssl->rwstate; }

void SSL_CTX_set_tmp_rsa_callback(SSL_CTX *ctx,
                                  RSA *(*cb)(SSL *ssl, int is_export,
                                             int keylength)) {
}

void SSL_set_tmp_rsa_callback(SSL *ssl, RSA *(*cb)(SSL *ssl, int is_export,
                                                   int keylength)) {
}

void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx,
                                 DH *(*callback)(SSL *ssl, int is_export,
                                                 int keylength)) {
  ctx->cert->dh_tmp_cb = callback;
}

void SSL_set_tmp_dh_callback(SSL *ssl, DH *(*callback)(SSL *ssl, int is_export,
                                                       int keylength)) {
  ssl->cert->dh_tmp_cb = callback;
}

int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint) {
  if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    return 0;
  }

  OPENSSL_free(ctx->psk_identity_hint);

  if (identity_hint != NULL) {
    ctx->psk_identity_hint = BUF_strdup(identity_hint);
    if (ctx->psk_identity_hint == NULL) {
      return 0;
    }
  } else {
    ctx->psk_identity_hint = NULL;
  }

  return 1;
}

int SSL_use_psk_identity_hint(SSL *ssl, const char *identity_hint) {
  if (ssl == NULL) {
    return 0;
  }

  if (identity_hint != NULL && strlen(identity_hint) > PSK_MAX_IDENTITY_LEN) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DATA_LENGTH_TOO_LONG);
    return 0;
  }

  /* Clear currently configured hint, if any. */
  OPENSSL_free(ssl->psk_identity_hint);
  ssl->psk_identity_hint = NULL;

  if (identity_hint != NULL) {
    ssl->psk_identity_hint = BUF_strdup(identity_hint);
    if (ssl->psk_identity_hint == NULL) {
      return 0;
    }
  }

  return 1;
}

const char *SSL_get_psk_identity_hint(const SSL *ssl) {
  if (ssl == NULL) {
    return NULL;
  }
  return ssl->psk_identity_hint;
}

const char *SSL_get_psk_identity(const SSL *ssl) {
  if (ssl == NULL || ssl->session == NULL) {
    return NULL;
  }

  return ssl->session->psk_identity;
}

void SSL_set_psk_client_callback(
    SSL *ssl, unsigned (*cb)(SSL *ssl, const char *hint, char *identity,
                             unsigned max_identity_len, uint8_t *psk,
                             unsigned max_psk_len)) {
  ssl->psk_client_callback = cb;
}

void SSL_CTX_set_psk_client_callback(
    SSL_CTX *ctx, unsigned (*cb)(SSL *ssl, const char *hint, char *identity,
                                 unsigned max_identity_len, uint8_t *psk,
                                 unsigned max_psk_len)) {
  ctx->psk_client_callback = cb;
}

void SSL_set_psk_server_callback(
    SSL *ssl, unsigned (*cb)(SSL *ssl, const char *identity, uint8_t *psk,
                             unsigned max_psk_len)) {
  ssl->psk_server_callback = cb;
}

void SSL_CTX_set_psk_server_callback(
    SSL_CTX *ctx, unsigned (*cb)(SSL *ssl, const char *identity,
                                 uint8_t *psk, unsigned max_psk_len)) {
  ctx->psk_server_callback = cb;
}

void SSL_CTX_set_msg_callback(SSL_CTX *ctx,
                              void (*cb)(int write_p, int version,
                                         int content_type, const void *buf,
                                         size_t len, SSL *ssl, void *arg)) {
  ctx->msg_callback = cb;
}

void SSL_CTX_set_msg_callback_arg(SSL_CTX *ctx, void *arg) {
  ctx->msg_callback_arg = arg;
}

void SSL_set_msg_callback(SSL *ssl,
                          void (*cb)(int write_p, int version, int content_type,
                                     const void *buf, size_t len, SSL *ssl,
                                     void *arg)) {
  ssl->msg_callback = cb;
}

void SSL_set_msg_callback_arg(SSL *ssl, void *arg) {
  ssl->msg_callback_arg = arg;
}

void SSL_CTX_set_keylog_callback(SSL_CTX *ctx,
                                 void (*cb)(const SSL *ssl, const char *line)) {
  ctx->keylog_callback = cb;
}

static int cbb_add_hex(CBB *cbb, const uint8_t *in, size_t in_len) {
  static const char hextable[] = "0123456789abcdef";
  uint8_t *out;
  size_t i;

  if (!CBB_add_space(cbb, &out, in_len * 2)) {
    return 0;
  }

  for (i = 0; i < in_len; i++) {
    *(out++) = (uint8_t)hextable[in[i] >> 4];
    *(out++) = (uint8_t)hextable[in[i] & 0xf];
  }

  return 1;
}

int ssl_log_rsa_client_key_exchange(const SSL *ssl,
                                    const uint8_t *encrypted_premaster,
                                    size_t encrypted_premaster_len,
                                    const uint8_t *premaster,
                                    size_t premaster_len) {
  if (ssl->ctx->keylog_callback == NULL) {
    return 1;
  }

  if (encrypted_premaster_len < 8) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  CBB cbb;
  uint8_t *out;
  size_t out_len;
  if (!CBB_init(&cbb, 4 + 16 + 1 + premaster_len * 2 + 1) ||
      !CBB_add_bytes(&cbb, (const uint8_t *)"RSA ", 4) ||
      /* Only the first 8 bytes of the encrypted premaster secret are
       * logged. */
      !cbb_add_hex(&cbb, encrypted_premaster, 8) ||
      !CBB_add_bytes(&cbb, (const uint8_t *)" ", 1) ||
      !cbb_add_hex(&cbb, premaster, premaster_len) ||
      !CBB_add_u8(&cbb, 0 /* NUL */) ||
      !CBB_finish(&cbb, &out, &out_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  ssl->ctx->keylog_callback(ssl, (const char *)out);
  OPENSSL_free(out);
  return 1;
}

int ssl_log_master_secret(const SSL *ssl, const uint8_t *client_random,
                          size_t client_random_len, const uint8_t *master,
                          size_t master_len) {
  if (ssl->ctx->keylog_callback == NULL) {
    return 1;
  }

  if (client_random_len != 32) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  CBB cbb;
  uint8_t *out;
  size_t out_len;
  if (!CBB_init(&cbb, 14 + 64 + 1 + master_len * 2 + 1) ||
      !CBB_add_bytes(&cbb, (const uint8_t *)"CLIENT_RANDOM ", 14) ||
      !cbb_add_hex(&cbb, client_random, 32) ||
      !CBB_add_bytes(&cbb, (const uint8_t *)" ", 1) ||
      !cbb_add_hex(&cbb, master, master_len) ||
      !CBB_add_u8(&cbb, 0 /* NUL */) ||
      !CBB_finish(&cbb, &out, &out_len)) {
    CBB_cleanup(&cbb);
    return 0;
  }

  ssl->ctx->keylog_callback(ssl, (const char *)out);
  OPENSSL_free(out);
  return 1;
}

int SSL_is_init_finished(const SSL *ssl) {
  return ssl->state == SSL_ST_OK;
}

int SSL_in_init(const SSL *ssl) {
  return (ssl->state & SSL_ST_INIT) != 0;
}

int SSL_in_false_start(const SSL *ssl) {
  return ssl->s3->tmp.in_false_start;
}

int SSL_cutthrough_complete(const SSL *ssl) {
  return SSL_in_false_start(ssl);
}

void SSL_get_structure_sizes(size_t *ssl_size, size_t *ssl_ctx_size,
                             size_t *ssl_session_size) {
  *ssl_size = sizeof(SSL);
  *ssl_ctx_size = sizeof(SSL_CTX);
  *ssl_session_size = sizeof(SSL_SESSION);
}

int ssl3_can_false_start(const SSL *ssl) {
  const SSL_CIPHER *const cipher = SSL_get_current_cipher(ssl);

  /* False Start only for TLS 1.2 with an ECDHE+AEAD cipher and ALPN or NPN. */
  return !SSL_IS_DTLS(ssl) &&
      SSL_version(ssl) >= TLS1_2_VERSION &&
      (ssl->s3->alpn_selected || ssl->s3->next_proto_neg_seen) &&
      cipher != NULL &&
      cipher->algorithm_mkey == SSL_kECDHE &&
      cipher->algorithm_mac == SSL_AEAD;
}

const SSL3_ENC_METHOD *ssl3_get_enc_method(uint16_t version) {
  switch (version) {
    case SSL3_VERSION:
      return &SSLv3_enc_data;

    case TLS1_VERSION:
    case TLS1_1_VERSION:
    case TLS1_2_VERSION:
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
      return &TLSv1_enc_data;

    default:
      return NULL;
  }
}

uint16_t ssl3_get_max_server_version(const SSL *ssl) {
  uint16_t max_version;

  if (SSL_IS_DTLS(ssl)) {
    max_version = (ssl->max_version != 0) ? ssl->max_version : DTLS1_2_VERSION;
    if (!(ssl->options & SSL_OP_NO_DTLSv1_2) &&
        DTLS1_2_VERSION >= max_version) {
      return DTLS1_2_VERSION;
    }
    if (!(ssl->options & SSL_OP_NO_DTLSv1) && DTLS1_VERSION >= max_version) {
      return DTLS1_VERSION;
    }
    return 0;
  }

  max_version = (ssl->max_version != 0) ? ssl->max_version : TLS1_2_VERSION;
  if (!(ssl->options & SSL_OP_NO_TLSv1_2) && TLS1_2_VERSION <= max_version) {
    return TLS1_2_VERSION;
  }
  if (!(ssl->options & SSL_OP_NO_TLSv1_1) && TLS1_1_VERSION <= max_version) {
    return TLS1_1_VERSION;
  }
  if (!(ssl->options & SSL_OP_NO_TLSv1) && TLS1_VERSION <= max_version) {
    return TLS1_VERSION;
  }
  if (!(ssl->options & SSL_OP_NO_SSLv3) && SSL3_VERSION <= max_version) {
    return SSL3_VERSION;
  }
  return 0;
}

uint16_t ssl3_get_mutual_version(SSL *ssl, uint16_t client_version) {
  uint16_t version = 0;

  if (SSL_IS_DTLS(ssl)) {
    /* Clamp client_version to max_version. */
    if (ssl->max_version != 0 && client_version < ssl->max_version) {
      client_version = ssl->max_version;
    }

    if (client_version <= DTLS1_2_VERSION &&
        !(ssl->options & SSL_OP_NO_DTLSv1_2)) {
      version = DTLS1_2_VERSION;
    } else if (client_version <= DTLS1_VERSION &&
               !(ssl->options & SSL_OP_NO_DTLSv1)) {
      version = DTLS1_VERSION;
    }

    /* Check against min_version. */
    if (version != 0 && ssl->min_version != 0 && version > ssl->min_version) {
      return 0;
    }
    return version;
  } else {
    /* Clamp client_version to max_version. */
    if (ssl->max_version != 0 && client_version > ssl->max_version) {
      client_version = ssl->max_version;
    }

    if (client_version >= TLS1_2_VERSION &&
        !(ssl->options & SSL_OP_NO_TLSv1_2)) {
      version = TLS1_2_VERSION;
    } else if (client_version >= TLS1_1_VERSION &&
               !(ssl->options & SSL_OP_NO_TLSv1_1)) {
      version = TLS1_1_VERSION;
    } else if (client_version >= TLS1_VERSION &&
               !(ssl->options & SSL_OP_NO_TLSv1)) {
      version = TLS1_VERSION;
    } else if (client_version >= SSL3_VERSION &&
               !(ssl->options & SSL_OP_NO_SSLv3)) {
      version = SSL3_VERSION;
    }

    /* Check against min_version. */
    if (version != 0 && ssl->min_version != 0 && version < ssl->min_version) {
      return 0;
    }
    return version;
  }
}

uint16_t ssl3_get_max_client_version(SSL *ssl) {
  uint32_t options = ssl->options;
  uint16_t version = 0;

  /* OpenSSL's API for controlling versions entails blacklisting individual
   * protocols. This has two problems. First, on the client, the protocol can
   * only express a contiguous range of versions. Second, a library consumer
   * trying to set a maximum version cannot disable protocol versions that get
   * added in a future version of the library.
   *
   * To account for both of these, OpenSSL interprets the client-side bitmask
   * as a min/max range by picking the lowest contiguous non-empty range of
   * enabled protocols. Note that this means it is impossible to set a maximum
   * version of TLS 1.2 in a future-proof way.
   *
   * By this scheme, the maximum version is the lowest version V such that V is
   * enabled and V+1 is disabled or unimplemented. */
  if (SSL_IS_DTLS(ssl)) {
    if (!(options & SSL_OP_NO_DTLSv1_2)) {
      version = DTLS1_2_VERSION;
    }
    if (!(options & SSL_OP_NO_DTLSv1) && (options & SSL_OP_NO_DTLSv1_2)) {
      version = DTLS1_VERSION;
    }
    if (ssl->max_version != 0 && version < ssl->max_version) {
      version = ssl->max_version;
    }
  } else {
    if (!(options & SSL_OP_NO_TLSv1_2)) {
      version = TLS1_2_VERSION;
    }
    if (!(options & SSL_OP_NO_TLSv1_1) && (options & SSL_OP_NO_TLSv1_2)) {
      version = TLS1_1_VERSION;
    }
    if (!(options & SSL_OP_NO_TLSv1) && (options & SSL_OP_NO_TLSv1_1)) {
      version = TLS1_VERSION;
    }
    if (!(options & SSL_OP_NO_SSLv3) && (options & SSL_OP_NO_TLSv1)) {
      version = SSL3_VERSION;
    }
    if (ssl->max_version != 0 && version > ssl->max_version) {
      version = ssl->max_version;
    }
  }

  return version;
}

int ssl3_is_version_enabled(SSL *ssl, uint16_t version) {
  if (SSL_IS_DTLS(ssl)) {
    if (ssl->max_version != 0 && version < ssl->max_version) {
      return 0;
    }
    if (ssl->min_version != 0 && version > ssl->min_version) {
      return 0;
    }

    switch (version) {
      case DTLS1_VERSION:
        return !(ssl->options & SSL_OP_NO_DTLSv1);

      case DTLS1_2_VERSION:
        return !(ssl->options & SSL_OP_NO_DTLSv1_2);

      default:
        return 0;
    }
  } else {
    if (ssl->max_version != 0 && version > ssl->max_version) {
      return 0;
    }
    if (ssl->min_version != 0 && version < ssl->min_version) {
      return 0;
    }

    switch (version) {
      case SSL3_VERSION:
        return !(ssl->options & SSL_OP_NO_SSLv3);

      case TLS1_VERSION:
        return !(ssl->options & SSL_OP_NO_TLSv1);

      case TLS1_1_VERSION:
        return !(ssl->options & SSL_OP_NO_TLSv1_1);

      case TLS1_2_VERSION:
        return !(ssl->options & SSL_OP_NO_TLSv1_2);

      default:
        return 0;
    }
  }
}

uint16_t ssl3_version_from_wire(const SSL *ssl, uint16_t wire_version) {
  if (!SSL_IS_DTLS(ssl)) {
    return wire_version;
  }

  uint16_t tls_version = ~wire_version;
  uint16_t version = tls_version + 0x0201;
  /* If either component overflowed, clamp it so comparisons still work. */
  if ((version >> 8) < (tls_version >> 8)) {
    version = 0xff00 | (version & 0xff);
  }
  if ((version & 0xff) < (tls_version & 0xff)) {
    version = (version & 0xff00) | 0xff;
  }
  /* DTLS 1.0 maps to TLS 1.1, not TLS 1.0. */
  if (version == TLS1_VERSION) {
    version = TLS1_1_VERSION;
  }
  return version;
}

uint16_t ssl3_protocol_version(const SSL *ssl) {
  assert(ssl->s3->have_version);
  return ssl3_version_from_wire(ssl, ssl->version);
}

int SSL_cache_hit(SSL *ssl) { return SSL_session_reused(ssl); }

int SSL_is_server(SSL *ssl) { return ssl->server; }

void SSL_CTX_set_select_certificate_cb(
    SSL_CTX *ctx, int (*cb)(const struct ssl_early_callback_ctx *)) {
  ctx->select_certificate_cb = cb;
}

void SSL_CTX_set_dos_protection_cb(
    SSL_CTX *ctx, int (*cb)(const struct ssl_early_callback_ctx *)) {
  ctx->dos_protection_cb = cb;
}

void SSL_set_renegotiate_mode(SSL *ssl, enum ssl_renegotiate_mode_t mode) {
  ssl->renegotiate_mode = mode;
}

void SSL_set_reject_peer_renegotiations(SSL *ssl, int reject) {
  SSL_set_renegotiate_mode(
      ssl, reject ? ssl_renegotiate_never : ssl_renegotiate_freely);
}

int SSL_get_rc4_state(const SSL *ssl, const RC4_KEY **read_key,
                      const RC4_KEY **write_key) {
  if (ssl->s3->aead_read_ctx == NULL || ssl->s3->aead_write_ctx == NULL) {
    return 0;
  }

  return EVP_AEAD_CTX_get_rc4_state(&ssl->s3->aead_read_ctx->ctx, read_key) &&
         EVP_AEAD_CTX_get_rc4_state(&ssl->s3->aead_write_ctx->ctx, write_key);
}

int SSL_get_ivs(const SSL *ssl, const uint8_t **out_read_iv,
                const uint8_t **out_write_iv, size_t *out_iv_len) {
  if (ssl->s3->aead_read_ctx == NULL || ssl->s3->aead_write_ctx == NULL) {
    return 0;
  }

  size_t write_iv_len;
  if (!EVP_AEAD_CTX_get_iv(&ssl->s3->aead_read_ctx->ctx, out_read_iv,
                           out_iv_len) ||
      !EVP_AEAD_CTX_get_iv(&ssl->s3->aead_write_ctx->ctx, out_write_iv,
                           &write_iv_len) ||
      *out_iv_len != write_iv_len) {
    return 0;
  }

  return 1;
}

static uint64_t be_to_u64(const uint8_t in[8]) {
  return (((uint64_t)in[0]) << 56) | (((uint64_t)in[1]) << 48) |
         (((uint64_t)in[2]) << 40) | (((uint64_t)in[3]) << 32) |
         (((uint64_t)in[4]) << 24) | (((uint64_t)in[5]) << 16) |
         (((uint64_t)in[6]) << 8) | ((uint64_t)in[7]);
}

uint64_t SSL_get_read_sequence(const SSL *ssl) {
  /* TODO(davidben): Internally represent sequence numbers as uint64_t. */
  if (SSL_IS_DTLS(ssl)) {
    /* max_seq_num already includes the epoch. */
    assert(ssl->d1->r_epoch == (ssl->d1->bitmap.max_seq_num >> 48));
    return ssl->d1->bitmap.max_seq_num;
  }
  return be_to_u64(ssl->s3->read_sequence);
}

uint64_t SSL_get_write_sequence(const SSL *ssl) {
  uint64_t ret = be_to_u64(ssl->s3->write_sequence);
  if (SSL_IS_DTLS(ssl)) {
    assert((ret >> 48) == 0);
    ret |= ((uint64_t)ssl->d1->w_epoch) << 48;
  }
  return ret;
}

uint8_t SSL_get_server_key_exchange_hash(const SSL *ssl) {
  return ssl->s3->tmp.server_key_exchange_hash;
}

size_t SSL_get_client_random(const SSL *ssl, uint8_t *out, size_t max_out) {
  if (max_out == 0) {
    return sizeof(ssl->s3->client_random);
  }
  if (max_out > sizeof(ssl->s3->client_random)) {
    max_out = sizeof(ssl->s3->client_random);
  }
  memcpy(out, ssl->s3->client_random, max_out);
  return max_out;
}

size_t SSL_get_server_random(const SSL *ssl, uint8_t *out, size_t max_out) {
  if (max_out == 0) {
    return sizeof(ssl->s3->server_random);
  }
  if (max_out > sizeof(ssl->s3->server_random)) {
    max_out = sizeof(ssl->s3->server_random);
  }
  memcpy(out, ssl->s3->server_random, max_out);
  return max_out;
}

const SSL_CIPHER *SSL_get_pending_cipher(const SSL *ssl) {
  if (!SSL_in_init(ssl)) {
    return NULL;
  }
  return ssl->s3->tmp.new_cipher;
}

void SSL_CTX_set_retain_only_sha256_of_client_certs(SSL_CTX *ctx, int enabled) {
  ctx->retain_only_sha256_of_client_certs = !!enabled;
}

int SSL_clear(SSL *ssl) {
  if (ssl->method == NULL) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_NO_METHOD_SPECIFIED);
    return 0;
  }

  if (ssl_clear_bad_session(ssl)) {
    SSL_SESSION_free(ssl->session);
    ssl->session = NULL;
  }

  ssl->hit = 0;
  ssl->shutdown = 0;

  /* SSL_clear may be called before or after the |ssl| is initialized in either
   * accept or connect state. In the latter case, SSL_clear should preserve the
   * half and reset |ssl->state| accordingly. */
  if (ssl->handshake_func != NULL) {
    if (ssl->server) {
      SSL_set_accept_state(ssl);
    } else {
      SSL_set_connect_state(ssl);
    }
  } else {
    assert(ssl->state == 0);
  }

  /* TODO(davidben): Some state on |ssl| is reset both in |SSL_new| and
   * |SSL_clear| because it is per-connection state rather than configuration
   * state. Per-connection state should be on |ssl->s3| and |ssl->d1| so it is
   * naturally reset at the right points between |SSL_new|, |SSL_clear|, and
   * |ssl3_new|. */

  ssl->rwstate = SSL_NOTHING;

  BUF_MEM_free(ssl->init_buf);
  ssl->init_buf = NULL;

  /* The ssl->d1->mtu is simultaneously configuration (preserved across
   * clear) and connection-specific state (gets reset).
   *
   * TODO(davidben): Avoid this. */
  unsigned mtu = 0;
  if (ssl->d1 != NULL) {
    mtu = ssl->d1->mtu;
  }

  ssl->method->ssl_free(ssl);
  if (!ssl->method->ssl_new(ssl)) {
    return 0;
  }

  if (SSL_IS_DTLS(ssl) && (SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
    ssl->d1->mtu = mtu;
  }

  ssl->client_version = ssl->version;

  return 1;
}

int SSL_CTX_sess_connect(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_connect_good(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_connect_renegotiate(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_accept(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_accept_renegotiate(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_accept_good(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_hits(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_cb_hits(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_misses(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_timeouts(const SSL_CTX *ctx) { return 0; }
int SSL_CTX_sess_cache_full(const SSL_CTX *ctx) { return 0; }
void ERR_load_SSL_strings(void) {}
void SSL_load_error_strings(void) {}
