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
 * Copyright (c) 1998-2006 The OpenSSL Project.  All rights reserved.
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

#include <boringssl/err.h>
#include <boringssl/lhash.h>
#include <boringssl/mem.h>
#include <boringssl/rand.h>

#include "internal.h"
#include "../crypto/internal.h"


/* The address of this is a magic value, a pointer to which is returned by
 * SSL_magic_pending_session_ptr(). It allows a session callback to indicate
 * that it needs to asynchronously fetch session information. */
static const char g_pending_session_magic = 0;

static CRYPTO_EX_DATA_CLASS g_ex_data_class =
    CRYPTO_EX_DATA_CLASS_INIT_WITH_APP_DATA;

static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *session);
static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *session);
static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *session, int lock);

SSL_SESSION *SSL_SESSION_new(void) {
  SSL_SESSION *session = OPENSSL_malloc(sizeof(SSL_SESSION));
  if (session == NULL) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return 0;
  }
  memset(session, 0, sizeof(SSL_SESSION));

  session->verify_result = 1; /* avoid 0 (= X509_V_OK) just in case */
  session->references = 1;
  session->timeout = SSL_DEFAULT_SESSION_TIMEOUT;
  session->time = (unsigned long)time(NULL);
  CRYPTO_new_ex_data(&session->ex_data);
  return session;
}

SSL_SESSION *SSL_SESSION_up_ref(SSL_SESSION *session) {
  if (session != NULL) {
    CRYPTO_refcount_inc(&session->references);
  }
  return session;
}

void SSL_SESSION_free(SSL_SESSION *session) {
  if (session == NULL ||
      !CRYPTO_refcount_dec_and_test_zero(&session->references)) {
    return;
  }

  CRYPTO_free_ex_data(&g_ex_data_class, session, &session->ex_data);

  OPENSSL_cleanse(session->master_key, sizeof(session->master_key));
  OPENSSL_cleanse(session->session_id, sizeof(session->session_id));
  X509_free(session->peer);
  sk_X509_pop_free(session->cert_chain, X509_free);
  OPENSSL_free(session->tlsext_hostname);
  OPENSSL_free(session->tlsext_tick);
  OPENSSL_free(session->tlsext_signed_cert_timestamp_list);
  OPENSSL_free(session->ocsp_response);
  OPENSSL_free(session->psk_identity);
  OPENSSL_cleanse(session, sizeof(*session));
  OPENSSL_free(session);
}

const uint8_t *SSL_SESSION_get_id(const SSL_SESSION *session,
                                  unsigned *out_len) {
  if (out_len != NULL) {
    *out_len = session->session_id_length;
  }
  return session->session_id;
}

long SSL_SESSION_get_timeout(const SSL_SESSION *session) {
  return session->timeout;
}

long SSL_SESSION_get_time(const SSL_SESSION *session) {
  if (session == NULL) {
    /* NULL should crash, but silently accept it here for compatibility. */
    return 0;
  }
  return session->time;
}

uint32_t SSL_SESSION_get_key_exchange_info(const SSL_SESSION *session) {
  return session->key_exchange_info;
}

X509 *SSL_SESSION_get0_peer(const SSL_SESSION *session) {
  return session->peer;
}

size_t SSL_SESSION_get_master_key(const SSL_SESSION *session, uint8_t *out,
                                  size_t max_out) {
  /* TODO(davidben): Fix master_key_length's type and remove these casts. */
  if (max_out == 0) {
    return (size_t)session->master_key_length;
  }
  if (max_out > (size_t)session->master_key_length) {
    max_out = (size_t)session->master_key_length;
  }
  memcpy(out, session->master_key, max_out);
  return max_out;
}

long SSL_SESSION_set_time(SSL_SESSION *session, long time) {
  if (session == NULL) {
    return 0;
  }

  session->time = time;
  return time;
}

long SSL_SESSION_set_timeout(SSL_SESSION *session, long timeout) {
  if (session == NULL) {
    return 0;
  }

  session->timeout = timeout;
  return 1;
}

int SSL_SESSION_set1_id_context(SSL_SESSION *session, const uint8_t *sid_ctx,
                                unsigned sid_ctx_len) {
  if (sid_ctx_len > SSL_MAX_SID_CTX_LENGTH) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SSL_SESSION_ID_CONTEXT_TOO_LONG);
    return 0;
  }

  session->sid_ctx_length = sid_ctx_len;
  memcpy(session->sid_ctx, sid_ctx, sid_ctx_len);

  return 1;
}

SSL_SESSION *SSL_magic_pending_session_ptr(void) {
  return (SSL_SESSION *)&g_pending_session_magic;
}

SSL_SESSION *SSL_get_session(const SSL *ssl)
{
  /* aka SSL_get0_session; gets 0 objects, just returns a copy of the pointer */
  return ssl->session;
}

SSL_SESSION *SSL_get1_session(SSL *ssl) {
  /* variant of SSL_get_session: caller really gets something */
  return SSL_SESSION_up_ref(ssl->session);
}

int SSL_SESSION_get_ex_new_index(long argl, void *argp,
                                 CRYPTO_EX_unused *unused,
                                 CRYPTO_EX_dup *dup_func,
                                 CRYPTO_EX_free *free_func) {
  int index;
  if (!CRYPTO_get_ex_new_index(&g_ex_data_class, &index, argl, argp, dup_func,
                               free_func)) {
    return -1;
  }
  return index;
}

int SSL_SESSION_set_ex_data(SSL_SESSION *session, int idx, void *arg) {
  return CRYPTO_set_ex_data(&session->ex_data, idx, arg);
}

void *SSL_SESSION_get_ex_data(const SSL_SESSION *session, int idx) {
  return CRYPTO_get_ex_data(&session->ex_data, idx);
}

int ssl_get_new_session(SSL *ssl, int is_server) {
  if (ssl->mode & SSL_MODE_NO_SESSION_CREATION) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_SESSION_MAY_NOT_BE_CREATED);
    return 0;
  }

  SSL_SESSION *session = SSL_SESSION_new();
  if (session == NULL) {
    return 0;
  }

  /* If the context has a default timeout, use it over the default. */
  if (ssl->initial_ctx->session_timeout != 0) {
    session->timeout = ssl->initial_ctx->session_timeout;
  }

  session->ssl_version = ssl->version;

  if (is_server) {
    if (ssl->tlsext_ticket_expected) {
      /* Don't set session IDs for sessions resumed with tickets. This will keep
       * them out of the session cache. */
      session->session_id_length = 0;
    } else {
      session->session_id_length = SSL3_SSL_SESSION_ID_LENGTH;
      if (!RAND_bytes(session->session_id, session->session_id_length)) {
        goto err;
      }
    }

    if (ssl->tlsext_hostname != NULL) {
      session->tlsext_hostname = BUF_strdup(ssl->tlsext_hostname);
      if (session->tlsext_hostname == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
        goto err;
      }
    }
  } else {
    session->session_id_length = 0;
  }

  if (ssl->sid_ctx_length > sizeof(session->sid_ctx)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    goto err;
  }
  memcpy(session->sid_ctx, ssl->sid_ctx, ssl->sid_ctx_length);
  session->sid_ctx_length = ssl->sid_ctx_length;

  session->verify_result = X509_V_OK;

  SSL_SESSION_free(ssl->session);
  ssl->session = session;
  return 1;

err:
  SSL_SESSION_free(session);
  return 0;
}

/* ssl_lookup_session looks up |session_id| in the session cache and sets
 * |*out_session| to an |SSL_SESSION| object if found. The caller takes
 * ownership of the result. */
static enum ssl_session_result_t ssl_lookup_session(
    SSL *ssl, SSL_SESSION **out_session, const uint8_t *session_id,
    size_t session_id_len) {
  *out_session = NULL;

  if (session_id_len == 0 || session_id_len > SSL_MAX_SSL_SESSION_ID_LENGTH) {
    return ssl_session_success;
  }

  SSL_SESSION *session;
  /* Try the internal cache, if it exists. */
  if (!(ssl->initial_ctx->session_cache_mode &
        SSL_SESS_CACHE_NO_INTERNAL_LOOKUP)) {
    SSL_SESSION data;
    data.ssl_version = ssl->version;
    data.session_id_length = session_id_len;
    memcpy(data.session_id, session_id, session_id_len);

    CRYPTO_MUTEX_lock_read(&ssl->initial_ctx->lock);
    session = lh_SSL_SESSION_retrieve(ssl->initial_ctx->sessions, &data);
    if (session != NULL) {
      SSL_SESSION_up_ref(session);
    }
    /* TODO(davidben): This should probably move it to the front of the list. */
    CRYPTO_MUTEX_unlock(&ssl->initial_ctx->lock);

    if (session != NULL) {
      *out_session = session;
      return ssl_session_success;
    }
  }

  /* Fall back to the external cache, if it exists. */
  if (ssl->initial_ctx->get_session_cb == NULL) {
    return ssl_session_success;
  }
  int copy = 1;
  session = ssl->initial_ctx->get_session_cb(ssl, (uint8_t *)session_id,
                                             session_id_len, &copy);
  if (session == NULL) {
    return ssl_session_success;
  }
  if (session == SSL_magic_pending_session_ptr()) {
    return ssl_session_retry;
  }

  /* Increment reference count now if the session callback asks us to do so
   * (note that if the session structures returned by the callback are shared
   * between threads, it must handle the reference count itself [i.e. copy ==
   * 0], or things won't be thread-safe). */
  if (copy) {
    SSL_SESSION_up_ref(session);
  }

  /* Add the externally cached session to the internal cache if necessary. */
  if (!(ssl->initial_ctx->session_cache_mode &
        SSL_SESS_CACHE_NO_INTERNAL_STORE)) {
    SSL_CTX_add_session(ssl->initial_ctx, session);
  }

  *out_session = session;
  return ssl_session_success;
}

enum ssl_session_result_t ssl_get_prev_session(
    SSL *ssl, SSL_SESSION **out_session, int *out_send_ticket,
    const struct ssl_early_callback_ctx *ctx) {
  /* This is used only by servers. */
  assert(ssl->server);
  SSL_SESSION *session = NULL;
  int renew_ticket = 0;

  /* If tickets are disabled, always behave as if no tickets are present. */
  const uint8_t *ticket = NULL;
  size_t ticket_len = 0;
  const int tickets_supported =
      !(SSL_get_options(ssl) & SSL_OP_NO_TICKET) &&
      ssl->version > SSL3_VERSION &&
      SSL_early_callback_ctx_extension_get(ctx, TLSEXT_TYPE_session_ticket,
                                           &ticket, &ticket_len);
  int from_cache = 0;
  if (tickets_supported && ticket_len > 0) {
    if (!tls_process_ticket(ssl, &session, &renew_ticket, ticket, ticket_len,
                            ctx->session_id, ctx->session_id_len)) {
      return ssl_session_error;
    }
  } else {
    /* The client didn't send a ticket, so the session ID is a real ID. */
    enum ssl_session_result_t lookup_ret = ssl_lookup_session(
        ssl, &session, ctx->session_id, ctx->session_id_len);
    if (lookup_ret != ssl_session_success) {
      return lookup_ret;
    }
    from_cache = 1;
  }

  if (session == NULL ||
      session->sid_ctx_length != ssl->sid_ctx_length ||
      memcmp(session->sid_ctx, ssl->sid_ctx, ssl->sid_ctx_length) != 0) {
    /* The client did not offer a suitable ticket or session ID. If supported,
     * the new session should use a ticket. */
    goto no_session;
  }

  if ((ssl->verify_mode & SSL_VERIFY_PEER) && ssl->sid_ctx_length == 0) {
    /* We can't be sure if this session is being used out of context, which is
     * especially important for SSL_VERIFY_PEER. The application should have
     * used SSL[_CTX]_set_session_id_context.
     *
     * For this error case, we generate an error instead of treating the event
     * like a cache miss (otherwise it would be easy for applications to
     * effectively disable the session cache by accident without anyone
     * noticing). */
    OPENSSL_PUT_ERROR(SSL, SSL_R_SESSION_ID_CONTEXT_UNINITIALIZED);
    SSL_SESSION_free(session);
    return ssl_session_error;
  }

  if (session->timeout < (long)(time(NULL) - session->time)) {
    if (from_cache) {
      /* The session was from the cache, so remove it. */
      SSL_CTX_remove_session(ssl->initial_ctx, session);
    }
    goto no_session;
  }

  *out_session = session;
  *out_send_ticket = renew_ticket;
  return ssl_session_success;

no_session:
  *out_session = NULL;
  *out_send_ticket = tickets_supported;
  SSL_SESSION_free(session);
  return ssl_session_success;
}

int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *session) {
  /* Although |session| is inserted into two structures (a doubly-linked list
   * and the hash table), |ctx| only takes one reference. */
  SSL_SESSION_up_ref(session);

  SSL_SESSION *old_session;
  CRYPTO_MUTEX_lock_write(&ctx->lock);
  if (!lh_SSL_SESSION_insert(ctx->sessions, &old_session, session)) {
    CRYPTO_MUTEX_unlock(&ctx->lock);
    SSL_SESSION_free(session);
    return 0;
  }

  if (old_session != NULL) {
    if (old_session == session) {
      /* |session| was already in the cache. */
      CRYPTO_MUTEX_unlock(&ctx->lock);
      SSL_SESSION_free(old_session);
      return 0;
    }

    /* There was a session ID collision. |old_session| must be removed from
     * the linked list and released. */
    SSL_SESSION_list_remove(ctx, old_session);
    SSL_SESSION_free(old_session);
  }

  SSL_SESSION_list_add(ctx, session);

  /* Enforce any cache size limits. */
  if (SSL_CTX_sess_get_cache_size(ctx) > 0) {
    while (SSL_CTX_sess_number(ctx) > SSL_CTX_sess_get_cache_size(ctx)) {
      if (!remove_session_lock(ctx, ctx->session_cache_tail, 0)) {
        break;
      }
    }
  }

  CRYPTO_MUTEX_unlock(&ctx->lock);
  return 1;
}

int SSL_CTX_remove_session(SSL_CTX *ctx, SSL_SESSION *session) {
  return remove_session_lock(ctx, session, 1);
}

static int remove_session_lock(SSL_CTX *ctx, SSL_SESSION *session, int lock) {
  int ret = 0;

  if (session != NULL && session->session_id_length != 0) {
    if (lock) {
      CRYPTO_MUTEX_lock_write(&ctx->lock);
    }
    SSL_SESSION *found_session = lh_SSL_SESSION_retrieve(ctx->sessions,
                                                         session);
    if (found_session == session) {
      ret = 1;
      found_session = lh_SSL_SESSION_delete(ctx->sessions, session);
      SSL_SESSION_list_remove(ctx, session);
    }

    if (lock) {
      CRYPTO_MUTEX_unlock(&ctx->lock);
    }

    if (ret) {
      found_session->not_resumable = 1;
      if (ctx->remove_session_cb != NULL) {
        ctx->remove_session_cb(ctx, found_session);
      }
      SSL_SESSION_free(found_session);
    }
  }

  return ret;
}

int SSL_set_session(SSL *ssl, SSL_SESSION *session) {
  if (ssl->session == session) {
    return 1;
  }

  SSL_SESSION_free(ssl->session);
  ssl->session = session;
  if (session != NULL) {
    SSL_SESSION_up_ref(session);
    ssl->verify_result = session->verify_result;
  }

  return 1;
}

long SSL_CTX_set_timeout(SSL_CTX *ctx, long timeout) {
  if (ctx == NULL) {
    return 0;
  }

  long old_timeout = ctx->session_timeout;
  ctx->session_timeout = timeout;
  return old_timeout;
}

long SSL_CTX_get_timeout(const SSL_CTX *ctx) {
  if (ctx == NULL) {
    return 0;
  }

  return ctx->session_timeout;
}

typedef struct timeout_param_st {
  SSL_CTX *ctx;
  long time;
  LHASH_OF(SSL_SESSION) *cache;
} TIMEOUT_PARAM;

static void timeout_doall_arg(SSL_SESSION *session, void *void_param) {
  TIMEOUT_PARAM *param = void_param;

  if (param->time == 0 ||
      param->time > (session->time + session->timeout)) {
    /* timeout */
    /* The reason we don't call SSL_CTX_remove_session() is to
     * save on locking overhead */
    (void) lh_SSL_SESSION_delete(param->cache, session);
    SSL_SESSION_list_remove(param->ctx, session);
    session->not_resumable = 1;
    if (param->ctx->remove_session_cb != NULL) {
      param->ctx->remove_session_cb(param->ctx, session);
    }
    SSL_SESSION_free(session);
  }
}

void SSL_CTX_flush_sessions(SSL_CTX *ctx, long time) {
  TIMEOUT_PARAM tp;

  tp.ctx = ctx;
  tp.cache = ctx->sessions;
  if (tp.cache == NULL) {
    return;
  }
  tp.time = time;
  CRYPTO_MUTEX_lock_write(&ctx->lock);
  lh_SSL_SESSION_doall_arg(tp.cache, timeout_doall_arg, &tp);
  CRYPTO_MUTEX_unlock(&ctx->lock);
}

int ssl_clear_bad_session(SSL *ssl) {
  if (ssl->session != NULL && !(ssl->shutdown & SSL_SENT_SHUTDOWN) &&
      !SSL_in_init(ssl)) {
    SSL_CTX_remove_session(ssl->ctx, ssl->session);
    return 1;
  }

  return 0;
}

/* locked by SSL_CTX in the calling function */
static void SSL_SESSION_list_remove(SSL_CTX *ctx, SSL_SESSION *session) {
  if (session->next == NULL || session->prev == NULL) {
    return;
  }

  if (session->next == (SSL_SESSION *)&ctx->session_cache_tail) {
    /* last element in list */
    if (session->prev == (SSL_SESSION *)&ctx->session_cache_head) {
      /* only one element in list */
      ctx->session_cache_head = NULL;
      ctx->session_cache_tail = NULL;
    } else {
      ctx->session_cache_tail = session->prev;
      session->prev->next = (SSL_SESSION *)&(ctx->session_cache_tail);
    }
  } else {
    if (session->prev == (SSL_SESSION *)&ctx->session_cache_head) {
      /* first element in list */
      ctx->session_cache_head = session->next;
      session->next->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    } else { /* middle of list */
      session->next->prev = session->prev;
      session->prev->next = session->next;
    }
  }
  session->prev = session->next = NULL;
}

static void SSL_SESSION_list_add(SSL_CTX *ctx, SSL_SESSION *session) {
  if (session->next != NULL && session->prev != NULL) {
    SSL_SESSION_list_remove(ctx, session);
  }

  if (ctx->session_cache_head == NULL) {
    ctx->session_cache_head = session;
    ctx->session_cache_tail = session;
    session->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    session->next = (SSL_SESSION *)&(ctx->session_cache_tail);
  } else {
    session->next = ctx->session_cache_head;
    session->next->prev = session;
    session->prev = (SSL_SESSION *)&(ctx->session_cache_head);
    ctx->session_cache_head = session;
  }
}

void SSL_CTX_sess_set_new_cb(SSL_CTX *ctx,
                             int (*cb)(SSL *ssl, SSL_SESSION *session)) {
  ctx->new_session_cb = cb;
}

int (*SSL_CTX_sess_get_new_cb(SSL_CTX *ctx))(SSL *ssl, SSL_SESSION *session) {
  return ctx->new_session_cb;
}

void SSL_CTX_sess_set_remove_cb(
    SSL_CTX *ctx, void (*cb)(SSL_CTX *ctx, SSL_SESSION *session)) {
  ctx->remove_session_cb = cb;
}

void (*SSL_CTX_sess_get_remove_cb(SSL_CTX *ctx))(SSL_CTX *ctx,
                                                 SSL_SESSION *session) {
  return ctx->remove_session_cb;
}

void SSL_CTX_sess_set_get_cb(SSL_CTX *ctx,
                             SSL_SESSION *(*cb)(SSL *ssl,
                                                uint8_t *id, int id_len,
                                                int *out_copy)) {
  ctx->get_session_cb = cb;
}

SSL_SESSION *(*SSL_CTX_sess_get_get_cb(SSL_CTX *ctx))(
    SSL *ssl, uint8_t *id, int id_len, int *out_copy) {
  return ctx->get_session_cb;
}

void SSL_CTX_set_info_callback(
    SSL_CTX *ctx, void (*cb)(const SSL *ssl, int type, int value)) {
  ctx->info_callback = cb;
}

void (*SSL_CTX_get_info_callback(SSL_CTX *ctx))(const SSL *ssl, int type,
                                                int value) {
  return ctx->info_callback;
}

void SSL_CTX_set_client_cert_cb(SSL_CTX *ctx, int (*cb)(SSL *ssl,
                                                        X509 **out_x509,
                                                        EVP_PKEY **out_pkey)) {
  ctx->client_cert_cb = cb;
}

int (*SSL_CTX_get_client_cert_cb(SSL_CTX *ctx))(SSL *ssl, X509 **out_x509,
                                                EVP_PKEY **out_pkey) {
  return ctx->client_cert_cb;
}

void SSL_CTX_set_channel_id_cb(SSL_CTX *ctx,
                               void (*cb)(SSL *ssl, EVP_PKEY **pkey)) {
  ctx->channel_id_cb = cb;
}

void (*SSL_CTX_get_channel_id_cb(SSL_CTX *ctx))(SSL *ssl, EVP_PKEY **pkey) {
  return ctx->channel_id_cb;
}
