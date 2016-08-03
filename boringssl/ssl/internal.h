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
 * OTHERWISE.
 */

#ifndef OPENSSL_HEADER_SSL_INTERNAL_H
#define OPENSSL_HEADER_SSL_INTERNAL_H

#include <boringssl/base.h>

#include <boringssl/aead.h>
#include <boringssl/pqueue.h>
#include <boringssl/ssl.h>
#include <boringssl/stack.h>

#if defined(OPENSSL_WINDOWS)
/* Windows defines struct timeval in winsock2.h. */
#pragma warning(push, 3)
#include <winsock2.h>
#pragma warning(pop)
#else
#include <sys/time.h>
#endif


/* Cipher suites. */

/* Bits for |algorithm_mkey| (key exchange algorithm). */
#define SSL_kRSA 0x00000001L
#define SSL_kDHE 0x00000002L
#define SSL_kECDHE 0x00000004L
/* SSL_kPSK is only set for plain PSK, not ECDHE_PSK. */
#define SSL_kPSK 0x00000008L

/* Bits for |algorithm_auth| (server authentication). */
#define SSL_aRSA 0x00000001L
#define SSL_aECDSA 0x00000002L
/* SSL_aPSK is set for both PSK and ECDHE_PSK. */
#define SSL_aPSK 0x00000004L

/* Bits for |algorithm_enc| (symmetric encryption). */
#define SSL_3DES 0x00000001L
#define SSL_RC4 0x00000002L
#define SSL_AES128 0x00000004L
#define SSL_AES256 0x00000008L
#define SSL_AES128GCM 0x00000010L
#define SSL_AES256GCM 0x00000020L
#define SSL_CHACHA20POLY1305_OLD 0x00000040L
#define SSL_eNULL 0x00000080L
#define SSL_CHACHA20POLY1305 0x00000100L

#define SSL_AES (SSL_AES128 | SSL_AES256 | SSL_AES128GCM | SSL_AES256GCM)

/* Bits for |algorithm_mac| (symmetric authentication). */
#define SSL_MD5 0x00000001L
#define SSL_SHA1 0x00000002L
#define SSL_SHA256 0x00000004L
#define SSL_SHA384 0x00000008L
/* SSL_AEAD is set for all AEADs. */
#define SSL_AEAD 0x00000010L

/* Bits for |algorithm_prf| (handshake digest). */
#define SSL_HANDSHAKE_MAC_DEFAULT 0x1
#define SSL_HANDSHAKE_MAC_SHA256 0x2
#define SSL_HANDSHAKE_MAC_SHA384 0x4

/* SSL_MAX_DIGEST is the number of digest types which exist. When adding a new
 * one, update the table in ssl_cipher.c. */
#define SSL_MAX_DIGEST 4

/* ssl_cipher_get_evp_aead sets |*out_aead| to point to the correct EVP_AEAD
 * object for |cipher| protocol version |version|. It sets |*out_mac_secret_len|
 * and |*out_fixed_iv_len| to the MAC key length and fixed IV length,
 * respectively. The MAC key length is zero except for legacy block and stream
 * ciphers. It returns 1 on success and 0 on error. */
int ssl_cipher_get_evp_aead(const EVP_AEAD **out_aead,
                            size_t *out_mac_secret_len,
                            size_t *out_fixed_iv_len,
                            const SSL_CIPHER *cipher, uint16_t version);

/* ssl_get_handshake_digest returns the |EVP_MD| corresponding to
 * |algorithm_prf|. It returns SHA-1 for |SSL_HANDSHAKE_DEFAULT|. The caller is
 * responsible for maintaining the additional MD5 digest and switching to
 * SHA-256 in TLS 1.2. */
const EVP_MD *ssl_get_handshake_digest(uint32_t algorithm_prf);

/* ssl_create_cipher_list evaluates |rule_str| according to the ciphers in
 * |ssl_method|. It sets |*out_cipher_list| to a newly-allocated
 * |ssl_cipher_preference_list_st| containing the result.
 * |*out_cipher_list_by_id| is set to a list of selected ciphers sorted by
 * id. It returns |(*out_cipher_list)->ciphers| on success and NULL on
 * failure. */
STACK_OF(SSL_CIPHER) *
ssl_create_cipher_list(const SSL_PROTOCOL_METHOD *ssl_method,
                       struct ssl_cipher_preference_list_st **out_cipher_list,
                       STACK_OF(SSL_CIPHER) **out_cipher_list_by_id,
                       const char *rule_str);

/* ssl_cipher_get_value returns the cipher suite id of |cipher|. */
uint16_t ssl_cipher_get_value(const SSL_CIPHER *cipher);

/* ssl_cipher_get_key_type returns the |EVP_PKEY_*| value corresponding to the
 * server key used in |cipher| or |EVP_PKEY_NONE| if there is none. */
int ssl_cipher_get_key_type(const SSL_CIPHER *cipher);

/* ssl_cipher_has_server_public_key returns 1 if |cipher| involves a server
 * public key in the key exchange, sent in a server Certificate message.
 * Otherwise it returns 0. */
int ssl_cipher_has_server_public_key(const SSL_CIPHER *cipher);

/* ssl_cipher_requires_server_key_exchange returns 1 if |cipher| requires a
 * ServerKeyExchange message. Otherwise it returns 0.
 *
 * Unlike |ssl_cipher_has_server_public_key|, this function may return zero
 * while still allowing |cipher| an optional ServerKeyExchange. This is the
 * case for plain PSK ciphers. */
int ssl_cipher_requires_server_key_exchange(const SSL_CIPHER *cipher);

/* ssl_cipher_get_record_split_len, for TLS 1.0 CBC mode ciphers, returns the
 * length of an encrypted 1-byte record, for use in record-splitting. Otherwise
 * it returns zero. */
size_t ssl_cipher_get_record_split_len(const SSL_CIPHER *cipher);


/* Encryption layer. */

/* SSL_AEAD_CTX contains information about an AEAD that is being used to encrypt
 * an SSL connection. */
struct ssl_aead_ctx_st {
  const SSL_CIPHER *cipher;
  EVP_AEAD_CTX ctx;
  /* fixed_nonce contains any bytes of the nonce that are fixed for all
   * records. */
  uint8_t fixed_nonce[12];
  uint8_t fixed_nonce_len, variable_nonce_len;
  /* variable_nonce_included_in_record is non-zero if the variable nonce
   * for a record is included as a prefix before the ciphertext. */
  char variable_nonce_included_in_record;
  /* random_variable_nonce is non-zero if the variable nonce is
   * randomly generated, rather than derived from the sequence
   * number. */
  char random_variable_nonce;
  /* omit_length_in_ad is non-zero if the length should be omitted in the
   * AEAD's ad parameter. */
  char omit_length_in_ad;
  /* omit_version_in_ad is non-zero if the version should be omitted
   * in the AEAD's ad parameter. */
  char omit_version_in_ad;
  /* xor_fixed_nonce is non-zero if the fixed nonce should be XOR'd into the
   * variable nonce rather than prepended. */
  char xor_fixed_nonce;
} /* SSL_AEAD_CTX */;

/* SSL_AEAD_CTX_new creates a newly-allocated |SSL_AEAD_CTX| using the supplied
 * key material. It returns NULL on error. Only one of |SSL_AEAD_CTX_open| or
 * |SSL_AEAD_CTX_seal| may be used with the resulting object, depending on
 * |direction|. |version| is the normalized protocol version, so DTLS 1.0 is
 * represented as 0x0301, not 0xffef. */
SSL_AEAD_CTX *SSL_AEAD_CTX_new(enum evp_aead_direction_t direction,
                               uint16_t version, const SSL_CIPHER *cipher,
                               const uint8_t *enc_key, size_t enc_key_len,
                               const uint8_t *mac_key, size_t mac_key_len,
                               const uint8_t *fixed_iv, size_t fixed_iv_len);

/* SSL_AEAD_CTX_free frees |ctx|. */
void SSL_AEAD_CTX_free(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_explicit_nonce_len returns the length of the explicit nonce for
 * |ctx|, if any. |ctx| may be NULL to denote the null cipher. */
size_t SSL_AEAD_CTX_explicit_nonce_len(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_max_overhead returns the maximum overhead of calling
 * |SSL_AEAD_CTX_seal|. |ctx| may be NULL to denote the null cipher. */
size_t SSL_AEAD_CTX_max_overhead(SSL_AEAD_CTX *ctx);

/* SSL_AEAD_CTX_open authenticates and decrypts |in_len| bytes from |in| and
 * writes the result to |out|. It returns one on success and zero on
 * error. |ctx| may be NULL to denote the null cipher.
 *
 * If |in| and |out| alias then |out| must be <= |in| + |explicit_nonce_len|. */
int SSL_AEAD_CTX_open(SSL_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len);

/* SSL_AEAD_CTX_seal encrypts and authenticates |in_len| bytes from |in| and
 * writes the result to |out|. It returns one on success and zero on
 * error. |ctx| may be NULL to denote the null cipher.
 *
 * If |in| and |out| alias then |out| + |explicit_nonce_len| must be <= |in| */
int SSL_AEAD_CTX_seal(SSL_AEAD_CTX *ctx, uint8_t *out, size_t *out_len,
                      size_t max_out, uint8_t type, uint16_t wire_version,
                      const uint8_t seqnum[8], const uint8_t *in,
                      size_t in_len);


/* DTLS replay bitmap. */

/* DTLS1_BITMAP maintains a sliding window of 64 sequence numbers to detect
 * replayed packets. It should be initialized by zeroing every field. */
typedef struct dtls1_bitmap_st {
  /* map is a bit mask of the last 64 sequence numbers. Bit
   * |1<<i| corresponds to |max_seq_num - i|. */
  uint64_t map;
  /* max_seq_num is the largest sequence number seen so far as a 64-bit
   * integer. */
  uint64_t max_seq_num;
} DTLS1_BITMAP;


/* Record layer. */

/* ssl_record_sequence_update increments the sequence number in |seq|. It
 * returns one on success and zero on wraparound. */
int ssl_record_sequence_update(uint8_t *seq, size_t seq_len);

/* ssl_record_prefix_len returns the length of the prefix before the ciphertext
 * of a record for |ssl|.
 *
 * TODO(davidben): Expose this as part of public API once the high-level
 * buffer-free APIs are available. */
size_t ssl_record_prefix_len(const SSL *ssl);

enum ssl_open_record_t {
  ssl_open_record_success,
  ssl_open_record_discard,
  ssl_open_record_partial,
  ssl_open_record_error,
};

/* tls_open_record decrypts a record from |in|.
 *
 * On success, it returns |ssl_open_record_success|. It sets |*out_type| to the
 * record type, |*out_len| to the plaintext length, and writes the record body
 * to |out|. It sets |*out_consumed| to the number of bytes of |in| consumed.
 * Note that |*out_len| may be zero.
 *
 * If a record was successfully processed but should be discarded, it returns
 * |ssl_open_record_discard| and sets |*out_consumed| to the number of bytes
 * consumed.
 *
 * If the input did not contain a complete record, it returns
 * |ssl_open_record_partial|. It sets |*out_consumed| to the total number of
 * bytes necessary. It is guaranteed that a successful call to |tls_open_record|
 * will consume at least that many bytes.
 *
 * On failure, it returns |ssl_open_record_error| and sets |*out_alert| to an
 * alert to emit.
 *
 * If |in| and |out| alias, |out| must be <= |in| + |ssl_record_prefix_len|. */
enum ssl_open_record_t tls_open_record(
    SSL *ssl, uint8_t *out_type, uint8_t *out, size_t *out_len,
    size_t *out_consumed, uint8_t *out_alert, size_t max_out, const uint8_t *in,
    size_t in_len);

/* dtls_open_record implements |tls_open_record| for DTLS. It never returns
 * |ssl_open_record_partial| but otherwise behaves analogously. */
enum ssl_open_record_t dtls_open_record(
    SSL *ssl, uint8_t *out_type, uint8_t *out, size_t *out_len,
    size_t *out_consumed, uint8_t *out_alert, size_t max_out, const uint8_t *in,
    size_t in_len);

/* ssl_seal_prefix_len returns the length of the prefix before the ciphertext
 * when sealing a record with |ssl|. Note that this value may differ from
 * |ssl_record_prefix_len| when TLS 1.0 CBC record-splitting is enabled. Sealing
 * a small record may also result in a smaller output than this value.
 *
 * TODO(davidben): Expose this as part of public API once the high-level
 * buffer-free APIs are available. */
size_t ssl_seal_prefix_len(const SSL *ssl);

/* ssl_max_seal_overhead returns the maximum overhead of sealing a record with
 * |ssl|. This includes |ssl_seal_prefix_len|.
 *
 * TODO(davidben): Expose this as part of public API once the high-level
 * buffer-free APIs are available. */
size_t ssl_max_seal_overhead(const SSL *ssl);

/* tls_seal_record seals a new record of type |type| and body |in| and writes it
 * to |out|. At most |max_out| bytes will be written. It returns one on success
 * and zero on error. If enabled, |tls_seal_record| implements TLS 1.0 CBC 1/n-1
 * record splitting and may write two records concatenated.
 *
 * For a large record, the ciphertext will begin |ssl_seal_prefix_len| bytes
 * into out. Aligning |out| appropriately may improve performance. It writes at
 * most |in_len| + |ssl_max_seal_overhead| bytes to |out|.
 *
 * If |in| and |out| alias, |out| + |ssl_seal_prefix_len| must be <= |in|. */
int tls_seal_record(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
                    uint8_t type, const uint8_t *in, size_t in_len);

enum dtls1_use_epoch_t {
  dtls1_use_previous_epoch,
  dtls1_use_current_epoch,
};

/* dtls_seal_record implements |tls_seal_record| for DTLS. |use_epoch| selects
 * which epoch's cipher state to use. */
int dtls_seal_record(SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
                     uint8_t type, const uint8_t *in, size_t in_len,
                     enum dtls1_use_epoch_t use_epoch);

/* ssl_set_read_state sets |ssl|'s read cipher state to |aead_ctx|. It takes
 * ownership of |aead_ctx|. */
void ssl_set_read_state(SSL *ssl, SSL_AEAD_CTX *aead_ctx);

/* ssl_set_write_state sets |ssl|'s write cipher state to |aead_ctx|. It takes
 * ownership of |aead_ctx|. */
void ssl_set_write_state(SSL *ssl, SSL_AEAD_CTX *aead_ctx);


/* Private key operations. */

/* ssl_has_private_key returns one if |ssl| has a private key
 * configured and zero otherwise. */
int ssl_has_private_key(SSL *ssl);

/* ssl_private_key_* call the corresponding function on the
 * |SSL_PRIVATE_KEY_METHOD| for |ssl|, if configured. Otherwise, they implement
 * the operation with |EVP_PKEY|. */

int ssl_private_key_type(SSL *ssl);

size_t ssl_private_key_max_signature_len(SSL *ssl);

enum ssl_private_key_result_t ssl_private_key_sign(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out, const EVP_MD *md,
    const uint8_t *in, size_t in_len);

enum ssl_private_key_result_t ssl_private_key_sign_complete(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);

enum ssl_private_key_result_t ssl_private_key_decrypt(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
    const uint8_t *in, size_t in_len);

enum ssl_private_key_result_t ssl_private_key_decrypt_complete(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out);


/* Custom extensions */

/* ssl_custom_extension (a.k.a. SSL_CUSTOM_EXTENSION) is a structure that
 * contains information about custom-extension callbacks. */
struct ssl_custom_extension {
  SSL_custom_ext_add_cb add_callback;
  void *add_arg;
  SSL_custom_ext_free_cb free_callback;
  SSL_custom_ext_parse_cb parse_callback;
  void *parse_arg;
  uint16_t value;
};

void SSL_CUSTOM_EXTENSION_free(SSL_CUSTOM_EXTENSION *custom_extension);

int custom_ext_add_clienthello(SSL *ssl, CBB *extensions);
int custom_ext_parse_serverhello(SSL *ssl, int *out_alert, uint16_t value,
                                 const CBS *extension);
int custom_ext_parse_clienthello(SSL *ssl, int *out_alert, uint16_t value,
                                 const CBS *extension);
int custom_ext_add_serverhello(SSL *ssl, CBB *extensions);


/* Handshake hash.
 *
 * The TLS handshake maintains a transcript of all handshake messages. At
 * various points in the protocol, this is either a handshake buffer, a rolling
 * hash (selected by cipher suite) or both. */

/* ssl3_init_handshake_buffer initializes the handshake buffer and resets the
 * handshake hash. It returns one success and zero on failure. */
int ssl3_init_handshake_buffer(SSL *ssl);

/* ssl3_init_handshake_hash initializes the handshake hash based on the pending
 * cipher and the contents of the handshake buffer. Subsequent calls to
 * |ssl3_update_handshake_hash| will update the rolling hash. It returns one on
 * success and zero on failure. It is an error to call this function after the
 * handshake buffer is released. */
int ssl3_init_handshake_hash(SSL *ssl);

/* ssl3_free_handshake_buffer releases the handshake buffer. Subsequent calls
 * to |ssl3_update_handshake_hash| will not update the handshake buffer. */
void ssl3_free_handshake_buffer(SSL *ssl);

/* ssl3_free_handshake_hash releases the handshake hash. */
void ssl3_free_handshake_hash(SSL *ssl);

/* ssl3_update_handshake_hash adds |in| to the handshake buffer and handshake
 * hash, whichever is enabled. It returns one on success and zero on failure. */
int ssl3_update_handshake_hash(SSL *ssl, const uint8_t *in, size_t in_len);


/* ECDH curves. */

#define SSL_CURVE_SECP256R1 23
#define SSL_CURVE_SECP384R1 24
#define SSL_CURVE_SECP521R1 25
#define SSL_CURVE_X25519 29

/* An SSL_ECDH_METHOD is an implementation of ECDH-like key exchanges for
 * TLS. */
struct ssl_ecdh_method_st {
  int nid;
  uint16_t curve_id;
  const char name[8];

  /* cleanup releases state in |ctx|. */
  void (*cleanup)(SSL_ECDH_CTX *ctx);

  /* generate_keypair generates a keypair and writes the public value to
   * |out_public_key|. It returns one on success and zero on error. */
  int (*generate_keypair)(SSL_ECDH_CTX *ctx, CBB *out_public_key);

  /* compute_secret performs a key exchange against |peer_key| and, on
   * success, returns one and sets |*out_secret| and |*out_secret_len| to
   * a newly-allocated buffer containing the shared secret. The caller must
   * release this buffer with |OPENSSL_free|. Otherwise, it returns zero and
   * sets |*out_alert| to an alert to send to the peer. */
  int (*compute_secret)(SSL_ECDH_CTX *ctx, uint8_t **out_secret,
                        size_t *out_secret_len, uint8_t *out_alert,
                        const uint8_t *peer_key, size_t peer_key_len);
} /* SSL_ECDH_METHOD */;

/* ssl_nid_to_curve_id looks up the curve corresponding to |nid|. On success, it
 * sets |*out_curve_id| to the curve ID and returns one. Otherwise, it returns
 * zero. */
int ssl_nid_to_curve_id(uint16_t *out_curve_id, int nid);

/* SSL_ECDH_CTX_init sets up |ctx| for use with curve |curve_id|. It returns one
 * on success and zero on error. */
int SSL_ECDH_CTX_init(SSL_ECDH_CTX *ctx, uint16_t curve_id);

/* SSL_ECDH_CTX_init_for_dhe sets up |ctx| for use with legacy DHE-based ciphers
 * where the server specifies a group. It takes ownership of |params|. */
void SSL_ECDH_CTX_init_for_dhe(SSL_ECDH_CTX *ctx, DH *params);

/* SSL_ECDH_CTX_cleanup releases memory associated with |ctx|. It is legal to
 * call it in the zero state. */
void SSL_ECDH_CTX_cleanup(SSL_ECDH_CTX *ctx);

/* The following functions call the corresponding method of
 * |SSL_ECDH_METHOD|. */
int SSL_ECDH_CTX_generate_keypair(SSL_ECDH_CTX *ctx, CBB *out_public_key);
int SSL_ECDH_CTX_compute_secret(SSL_ECDH_CTX *ctx, uint8_t **out_secret,
                                size_t *out_secret_len, uint8_t *out_alert,
                                const uint8_t *peer_key, size_t peer_key_len);


/* Transport buffers. */

/* ssl_read_buffer returns a pointer to contents of the read buffer. */
uint8_t *ssl_read_buffer(SSL *ssl);

/* ssl_read_buffer_len returns the length of the read buffer. */
size_t ssl_read_buffer_len(const SSL *ssl);

/* ssl_read_buffer_extend_to extends the read buffer to the desired length. For
 * TLS, it reads to the end of the buffer until the buffer is |len| bytes
 * long. For DTLS, it reads a new packet and ignores |len|. It returns one on
 * success, zero on EOF, and a negative number on error.
 *
 * It is an error to call |ssl_read_buffer_extend_to| in DTLS when the buffer is
 * non-empty. */
int ssl_read_buffer_extend_to(SSL *ssl, size_t len);

/* ssl_read_buffer_consume consumes |len| bytes from the read buffer. It
 * advances the data pointer and decrements the length. The memory consumed will
 * remain valid until the next call to |ssl_read_buffer_extend| or it is
 * discarded with |ssl_read_buffer_discard|. */
void ssl_read_buffer_consume(SSL *ssl, size_t len);

/* ssl_read_buffer_discard discards the consumed bytes from the read buffer. If
 * the buffer is now empty, it releases memory used by it. */
void ssl_read_buffer_discard(SSL *ssl);

/* ssl_read_buffer_clear releases all memory associated with the read buffer and
 * zero-initializes it. */
void ssl_read_buffer_clear(SSL *ssl);

/* ssl_write_buffer_is_pending returns one if the write buffer has pending data
 * and zero if is empty. */
int ssl_write_buffer_is_pending(const SSL *ssl);

/* ssl_write_buffer_init initializes the write buffer. On success, it sets
 * |*out_ptr| to the start of the write buffer with space for up to |max_len|
 * bytes. It returns one on success and zero on failure. Call
 * |ssl_write_buffer_set_len| to complete initialization. */
int ssl_write_buffer_init(SSL *ssl, uint8_t **out_ptr, size_t max_len);

/* ssl_write_buffer_set_len is called after |ssl_write_buffer_init| to complete
 * initialization after |len| bytes are written to the buffer. */
void ssl_write_buffer_set_len(SSL *ssl, size_t len);

/* ssl_write_buffer_flush flushes the write buffer to the transport. It returns
 * one on success and <= 0 on error. For DTLS, whether or not the write
 * succeeds, the write buffer will be cleared. */
int ssl_write_buffer_flush(SSL *ssl);

/* ssl_write_buffer_clear releases all memory associated with the write buffer
 * and zero-initializes it. */
void ssl_write_buffer_clear(SSL *ssl);


/* Underdocumented functions.
 *
 * Functions below here haven't been touched up and may be underdocumented. */

#define c2l(c, l)                                                            \
  (l = ((unsigned long)(*((c)++))), l |= (((unsigned long)(*((c)++))) << 8), \
   l |= (((unsigned long)(*((c)++))) << 16),                                 \
   l |= (((unsigned long)(*((c)++))) << 24))

/* NOTE - c is not incremented as per c2l */
#define c2ln(c, l1, l2, n)                       \
  {                                              \
    c += n;                                      \
    l1 = l2 = 0;                                 \
    switch (n) {                                 \
      case 8:                                    \
        l2 = ((unsigned long)(*(--(c)))) << 24;  \
      case 7:                                    \
        l2 |= ((unsigned long)(*(--(c)))) << 16; \
      case 6:                                    \
        l2 |= ((unsigned long)(*(--(c)))) << 8;  \
      case 5:                                    \
        l2 |= ((unsigned long)(*(--(c))));       \
      case 4:                                    \
        l1 = ((unsigned long)(*(--(c)))) << 24;  \
      case 3:                                    \
        l1 |= ((unsigned long)(*(--(c)))) << 16; \
      case 2:                                    \
        l1 |= ((unsigned long)(*(--(c)))) << 8;  \
      case 1:                                    \
        l1 |= ((unsigned long)(*(--(c))));       \
    }                                            \
  }

#define l2c(l, c)                            \
  (*((c)++) = (uint8_t)(((l)) & 0xff),       \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 24) & 0xff))

#define n2l(c, l)                          \
  (l = ((unsigned long)(*((c)++))) << 24,  \
   l |= ((unsigned long)(*((c)++))) << 16, \
   l |= ((unsigned long)(*((c)++))) << 8, l |= ((unsigned long)(*((c)++))))

#define l2n(l, c)                            \
  (*((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l)) & 0xff))

#define l2n8(l, c)                           \
  (*((c)++) = (uint8_t)(((l) >> 56) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 48) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 40) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 32) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 24) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 16) & 0xff), \
   *((c)++) = (uint8_t)(((l) >> 8) & 0xff),  \
   *((c)++) = (uint8_t)(((l)) & 0xff))

/* NOTE - c is not incremented as per l2c */
#define l2cn(l1, l2, c, n)                               \
  {                                                      \
    c += n;                                              \
    switch (n) {                                         \
      case 8:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 24) & 0xff); \
      case 7:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 16) & 0xff); \
      case 6:                                            \
        *(--(c)) = (uint8_t)(((l2) >> 8) & 0xff);  \
      case 5:                                            \
        *(--(c)) = (uint8_t)(((l2)) & 0xff);       \
      case 4:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 24) & 0xff); \
      case 3:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 16) & 0xff); \
      case 2:                                            \
        *(--(c)) = (uint8_t)(((l1) >> 8) & 0xff);  \
      case 1:                                            \
        *(--(c)) = (uint8_t)(((l1)) & 0xff);       \
    }                                                    \
  }

#define n2s(c, s) \
  ((s = (((unsigned int)(c[0])) << 8) | (((unsigned int)(c[1])))), c += 2)

#define s2n(s, c)                              \
  ((c[0] = (uint8_t)(((s) >> 8) & 0xff), \
    c[1] = (uint8_t)(((s)) & 0xff)),     \
   c += 2)

#define n2l3(c, l)                                                         \
  ((l = (((unsigned long)(c[0])) << 16) | (((unsigned long)(c[1])) << 8) | \
        (((unsigned long)(c[2])))),                                        \
   c += 3)

#define l2n3(l, c)                              \
  ((c[0] = (uint8_t)(((l) >> 16) & 0xff), \
    c[1] = (uint8_t)(((l) >> 8) & 0xff),  \
    c[2] = (uint8_t)(((l)) & 0xff)),      \
   c += 3)

/* LOCAL STUFF */

#define TLSEXT_CHANNEL_ID_SIZE 128

/* Check if an SSL structure is using DTLS */
#define SSL_IS_DTLS(ssl) (ssl->method->is_dtls)

/* From RFC4492, used in encoding the curve type in ECParameters */
#define NAMED_CURVE_TYPE 3

enum ssl_hash_message_t {
  ssl_dont_hash_message,
  ssl_hash_message,
};

/* Structure containing decoded values of signature algorithms extension */
typedef struct tls_sigalgs_st {
  uint8_t rsign;
  uint8_t rhash;
} TLS_SIGALGS;

typedef struct cert_st {
  X509 *x509;
  EVP_PKEY *privatekey;
  /* Chain for this certificate */
  STACK_OF(X509) *chain;

  /* key_method, if non-NULL, is a set of callbacks to call for private key
   * operations. */
  const SSL_PRIVATE_KEY_METHOD *key_method;

  /* For clients the following masks are of *disabled* key and auth algorithms
   * based on the current configuration.
   *
   * TODO(davidben): Remove these. They get checked twice: when sending the
   * ClientHello and when processing the ServerHello. */
  uint32_t mask_k;
  uint32_t mask_a;

  DH *dh_tmp;
  DH *(*dh_tmp_cb)(SSL *ssl, int is_export, int keysize);

  /* peer_sigalgs are the algorithm/hash pairs that the peer supports. These
   * are taken from the contents of signature algorithms extension for a server
   * or from the CertificateRequest for a client. */
  TLS_SIGALGS *peer_sigalgs;
  /* peer_sigalgslen is the number of entries in |peer_sigalgs|. */
  size_t peer_sigalgslen;

  /* digest_nids, if non-NULL, is the set of digests supported by |privatekey|
   * in decreasing order of preference. */
  int *digest_nids;
  size_t num_digest_nids;

  /* Certificate setup callback: if set is called whenever a
   * certificate may be required (client or server). the callback
   * can then examine any appropriate parameters and setup any
   * certificates required. This allows advanced applications
   * to select certificates on the fly: for example based on
   * supported signature algorithms or curves. */
  int (*cert_cb)(SSL *ssl, void *arg);
  void *cert_cb_arg;

  /* Optional X509_STORE for certificate validation. If NULL the parent SSL_CTX
   * store is used instead. */
  X509_STORE *verify_store;
} CERT;

/* SSL_METHOD is a compatibility structure to support the legacy version-locked
 * methods. */
struct ssl_method_st {
  /* version, if non-zero, is the only protocol version acceptable to an
   * SSL_CTX initialized from this method. */
  uint16_t version;
  /* method is the underlying SSL_PROTOCOL_METHOD that initializes the
   * SSL_CTX. */
  const SSL_PROTOCOL_METHOD *method;
};

/* Used to hold functions for SSLv2 or SSLv3/TLSv1 functions */
struct ssl_protocol_method_st {
  /* is_dtls is one if the protocol is DTLS and zero otherwise. */
  char is_dtls;
  int (*ssl_new)(SSL *ssl);
  void (*ssl_free)(SSL *ssl);
  int (*ssl_accept)(SSL *ssl);
  int (*ssl_connect)(SSL *ssl);
  long (*ssl_get_message)(SSL *ssl, int header_state, int body_state,
                          int msg_type, long max,
                          enum ssl_hash_message_t hash_message, int *ok);
  int (*ssl_read_app_data)(SSL *ssl, uint8_t *buf, int len, int peek);
  int (*ssl_read_change_cipher_spec)(SSL *ssl);
  void (*ssl_read_close_notify)(SSL *ssl);
  int (*ssl_write_app_data)(SSL *ssl, const void *buf_, int len);
  int (*ssl_dispatch_alert)(SSL *ssl);
  /* supports_cipher returns one if |cipher| is supported by this protocol and
   * zero otherwise. */
  int (*supports_cipher)(const SSL_CIPHER *cipher);
  /* Handshake header length */
  unsigned int hhlen;
  /* Set the handshake header */
  int (*set_handshake_header)(SSL *ssl, int type, unsigned long len);
  /* Write out handshake message */
  int (*do_write)(SSL *ssl);
};

/* This is for the SSLv3/TLSv1.0 differences in crypto/hash stuff It is a bit
 * of a mess of functions, but hell, think of it as an opaque structure. */
struct ssl3_enc_method {
  /* prf computes the PRF function for |ssl|. It writes |out_len| bytes to
   * |out|, using |secret| as the secret and |label| as the label. |seed1| and
   * |seed2| are concatenated to form the seed parameter. It returns one on
   * success and zero on failure. */
  int (*prf)(const SSL *ssl, uint8_t *out, size_t out_len,
             const uint8_t *secret, size_t secret_len, const char *label,
             size_t label_len, const uint8_t *seed1, size_t seed1_len,
             const uint8_t *seed2, size_t seed2_len);
  int (*final_finish_mac)(SSL *ssl, int from_server, uint8_t *out);
  int (*cert_verify_mac)(SSL *, int, uint8_t *);
};

#define SSL_HM_HEADER_LENGTH(ssl) ssl->method->hhlen
#define ssl_handshake_start(ssl) \
  (((uint8_t *)ssl->init_buf->data) + ssl->method->hhlen)
#define ssl_set_handshake_header(ssl, htype, len) \
  ssl->method->set_handshake_header(ssl, htype, len)
#define ssl_do_write(ssl) ssl->method->do_write(ssl)

/* lengths of messages */
#define DTLS1_COOKIE_LENGTH 256

#define DTLS1_RT_HEADER_LENGTH 13

#define DTLS1_HM_HEADER_LENGTH 12

#define DTLS1_CCS_HEADER_LENGTH 1

#define DTLS1_AL_HEADER_LENGTH 2

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |is_ccs| and |epoch| are only used in the latter and
 * should be moved elsewhere. */
struct hm_header_st {
  uint8_t type;
  uint32_t msg_len;
  uint16_t seq;
  uint32_t frag_off;
  uint32_t frag_len;
  int is_ccs;
  /* epoch, for buffered outgoing messages, is the epoch the message was
   * originally sent in. */
  uint16_t epoch;
};

/* TODO(davidben): This structure is used for both incoming messages and
 * outgoing messages. |fragment| and |reassembly| are only used in the former
 * and should be moved elsewhere. */
typedef struct hm_fragment_st {
  struct hm_header_st msg_header;
  uint8_t *fragment;
  uint8_t *reassembly;
} hm_fragment;

typedef struct dtls1_state_st {
  /* send_cookie is true if we are resending the ClientHello
   * with a cookie from a HelloVerifyRequest. */
  unsigned int send_cookie;

  uint8_t cookie[DTLS1_COOKIE_LENGTH];
  size_t cookie_len;

  /* The current data and handshake epoch.  This is initially undefined, and
   * starts at zero once the initial handshake is completed. */
  uint16_t r_epoch;
  uint16_t w_epoch;

  /* records being received in the current epoch */
  DTLS1_BITMAP bitmap;

  /* handshake message numbers.
   * TODO(davidben): It doesn't make much sense to store both of these. Only
   * store one. */
  uint16_t handshake_write_seq;
  uint16_t next_handshake_write_seq;

  uint16_t handshake_read_seq;

  /* save last sequence number for retransmissions */
  uint8_t last_write_sequence[8];

  /* buffered_messages is a priority queue of incoming handshake messages that
   * have yet to be processed.
   *
   * TODO(davidben): This data structure may as well be a ring buffer of fixed
   * size. */
  pqueue buffered_messages;

  /* send_messages is a priority queue of outgoing handshake messages sent in
   * the most recent handshake flight.
   *
   * TODO(davidben): This data structure may as well be a STACK_OF(T). */
  pqueue sent_messages;

  unsigned int mtu; /* max DTLS packet size */

  struct hm_header_st w_msg_hdr;

  /* num_timeouts is the number of times the retransmit timer has fired since
   * the last time it was reset. */
  unsigned int num_timeouts;

  /* Indicates when the last handshake msg or heartbeat sent will
   * timeout. */
  struct timeval next_timeout;

  /* Timeout duration */
  unsigned short timeout_duration;
} DTLS1_STATE;

extern const SSL3_ENC_METHOD TLSv1_enc_data;
extern const SSL3_ENC_METHOD SSLv3_enc_data;
extern const SRTP_PROTECTION_PROFILE kSRTPProfiles[];

int ssl_clear_bad_session(SSL *ssl);
CERT *ssl_cert_new(void);
CERT *ssl_cert_dup(CERT *cert);
void ssl_cert_clear_certs(CERT *c);
void ssl_cert_free(CERT *c);
int ssl_get_new_session(SSL *ssl, int is_server);

enum ssl_session_result_t {
  ssl_session_success,
  ssl_session_error,
  ssl_session_retry,
};

/* ssl_get_prev_session looks up the previous session based on |ctx|. On
 * success, it sets |*out_session| to the session or NULL if none was found. It
 * sets |*out_send_ticket| to whether a ticket should be sent at the end of the
 * handshake. If the session could not be looked up synchronously, it returns
 * |ssl_session_retry| and should be called again. Otherwise, it returns
 * |ssl_session_error|.  */
enum ssl_session_result_t ssl_get_prev_session(
    SSL *ssl, SSL_SESSION **out_session, int *out_send_ticket,
    const struct ssl_early_callback_ctx *ctx);

STACK_OF(SSL_CIPHER) *ssl_bytes_to_cipher_list(SSL *ssl, const CBS *cbs);
void ssl_cipher_preference_list_free(
    struct ssl_cipher_preference_list_st *cipher_list);
struct ssl_cipher_preference_list_st *ssl_get_cipher_preferences(SSL *ssl);

int ssl_cert_set0_chain(CERT *cert, STACK_OF(X509) *chain);
int ssl_cert_set1_chain(CERT *cert, STACK_OF(X509) *chain);
int ssl_cert_add0_chain_cert(CERT *cert, X509 *x509);
int ssl_cert_add1_chain_cert(CERT *cert, X509 *x509);
void ssl_cert_set_cert_cb(CERT *cert,
                          int (*cb)(SSL *ssl, void *arg), void *arg);

int ssl_verify_cert_chain(SSL *ssl, STACK_OF(X509) *cert_chain);
int ssl_add_cert_chain(SSL *ssl, unsigned long *l);
void ssl_update_cache(SSL *ssl, int mode);

/* ssl_get_compatible_server_ciphers determines the key exchange and
 * authentication cipher suite masks compatible with the server configuration
 * and current ClientHello parameters of |ssl|. It sets |*out_mask_k| to the key
 * exchange mask and |*out_mask_a| to the authentication mask. */
void ssl_get_compatible_server_ciphers(SSL *ssl, uint32_t *out_mask_k,
                                       uint32_t *out_mask_a);

STACK_OF(SSL_CIPHER) *ssl_get_ciphers_by_id(SSL *ssl);
int ssl_verify_alarm_type(long type);

/* ssl_fill_hello_random fills a client_random or server_random field of length
 * |len|. It returns one on success and zero on failure. */
int ssl_fill_hello_random(uint8_t *out, size_t len, int is_server);

int ssl3_send_server_certificate(SSL *ssl);
int ssl3_send_new_session_ticket(SSL *ssl);
int ssl3_send_certificate_status(SSL *ssl);
int ssl3_get_finished(SSL *ssl, int state_a, int state_b);
int ssl3_send_change_cipher_spec(SSL *ssl, int state_a, int state_b);
void ssl3_cleanup_key_block(SSL *ssl);
int ssl3_do_write(SSL *ssl, int type);
int ssl3_send_alert(SSL *ssl, int level, int desc);
int ssl3_get_req_cert_type(SSL *ssl, uint8_t *p);
long ssl3_get_message(SSL *ssl, int header_state, int body_state, int msg_type,
                      long max, enum ssl_hash_message_t hash_message, int *ok);

/* ssl3_hash_current_message incorporates the current handshake message into the
 * handshake hash. It returns one on success and zero on allocation failure. */
int ssl3_hash_current_message(SSL *ssl);

/* ssl3_cert_verify_hash writes the CertificateVerify hash into the bytes
 * pointed to by |out| and writes the number of bytes to |*out_len|. |out| must
 * have room for EVP_MAX_MD_SIZE bytes. For TLS 1.2 and up, |*out_md| is used
 * for the hash function, otherwise the hash function depends on |pkey_type|
 * and is written to |*out_md|. It returns one on success and zero on
 * failure. */
int ssl3_cert_verify_hash(SSL *ssl, uint8_t *out, size_t *out_len,
                          const EVP_MD **out_md, int pkey_type);

int ssl3_send_finished(SSL *ssl, int a, int b);
int ssl3_supports_cipher(const SSL_CIPHER *cipher);
int ssl3_dispatch_alert(SSL *ssl);
int ssl3_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek);
int ssl3_read_change_cipher_spec(SSL *ssl);
void ssl3_read_close_notify(SSL *ssl);
int ssl3_read_bytes(SSL *ssl, int type, uint8_t *buf, int len, int peek);
int ssl3_write_app_data(SSL *ssl, const void *buf, int len);
int ssl3_write_bytes(SSL *ssl, int type, const void *buf, int len);
int ssl3_output_cert_chain(SSL *ssl);
const SSL_CIPHER *ssl3_choose_cipher(
    SSL *ssl, STACK_OF(SSL_CIPHER) *clnt,
    struct ssl_cipher_preference_list_st *srvr);

int ssl3_new(SSL *ssl);
void ssl3_free(SSL *ssl);
int ssl3_accept(SSL *ssl);
int ssl3_connect(SSL *ssl);

int ssl3_set_handshake_header(SSL *ssl, int htype, unsigned long len);
int ssl3_handshake_write(SSL *ssl);

int dtls1_do_handshake_write(SSL *ssl, enum dtls1_use_epoch_t use_epoch);
int dtls1_read_app_data(SSL *ssl, uint8_t *buf, int len, int peek);
int dtls1_read_change_cipher_spec(SSL *ssl);
void dtls1_read_close_notify(SSL *ssl);
int dtls1_read_bytes(SSL *ssl, int type, uint8_t *buf, int len, int peek);
void dtls1_set_message_header(SSL *ssl, uint8_t mt, unsigned long len,
                              unsigned short seq_num, unsigned long frag_off,
                              unsigned long frag_len);

int dtls1_write_app_data(SSL *ssl, const void *buf, int len);
int dtls1_write_bytes(SSL *ssl, int type, const void *buf, int len,
                      enum dtls1_use_epoch_t use_epoch);

int dtls1_send_change_cipher_spec(SSL *ssl, int a, int b);
int dtls1_send_finished(SSL *ssl, int a, int b, const char *sender, int slen);
int dtls1_read_failed(SSL *ssl, int code);
int dtls1_buffer_message(SSL *ssl);
int dtls1_retransmit_buffered_messages(SSL *ssl);
void dtls1_clear_record_buffer(SSL *ssl);
void dtls1_get_message_header(uint8_t *data, struct hm_header_st *msg_hdr);
int dtls1_check_timeout_num(SSL *ssl);
int dtls1_set_handshake_header(SSL *ssl, int type, unsigned long len);
int dtls1_handshake_write(SSL *ssl);

int dtls1_supports_cipher(const SSL_CIPHER *cipher);
void dtls1_start_timer(SSL *ssl);
void dtls1_stop_timer(SSL *ssl);
int dtls1_is_timer_expired(SSL *ssl);
void dtls1_double_timeout(SSL *ssl);
unsigned int dtls1_min_mtu(void);
void dtls1_hm_fragment_free(hm_fragment *frag);

/* some client-only functions */
int ssl3_send_client_hello(SSL *ssl);
int ssl3_get_server_hello(SSL *ssl);
int ssl3_get_certificate_request(SSL *ssl);
int ssl3_get_new_session_ticket(SSL *ssl);
int ssl3_get_cert_status(SSL *ssl);
int ssl3_get_server_done(SSL *ssl);
int ssl3_send_cert_verify(SSL *ssl);
int ssl3_send_client_certificate(SSL *ssl);
int ssl_do_client_cert_cb(SSL *ssl, X509 **px509, EVP_PKEY **ppkey);
int ssl3_send_client_key_exchange(SSL *ssl);
int ssl3_get_server_key_exchange(SSL *ssl);
int ssl3_get_server_certificate(SSL *ssl);
int ssl3_send_next_proto(SSL *ssl);
int ssl3_send_channel_id(SSL *ssl);
int ssl3_verify_server_cert(SSL *ssl);

/* some server-only functions */
int ssl3_get_initial_bytes(SSL *ssl);
int ssl3_get_v2_client_hello(SSL *ssl);
int ssl3_get_client_hello(SSL *ssl);
int ssl3_send_server_hello(SSL *ssl);
int ssl3_send_server_key_exchange(SSL *ssl);
int ssl3_send_certificate_request(SSL *ssl);
int ssl3_send_server_done(SSL *ssl);
int ssl3_get_client_certificate(SSL *ssl);
int ssl3_get_client_key_exchange(SSL *ssl);
int ssl3_get_cert_verify(SSL *ssl);
int ssl3_get_next_proto(SSL *ssl);
int ssl3_get_channel_id(SSL *ssl);

int dtls1_new(SSL *ssl);
int dtls1_accept(SSL *ssl);
int dtls1_connect(SSL *ssl);
void dtls1_free(SSL *ssl);

long dtls1_get_message(SSL *ssl, int st1, int stn, int mt, long max,
                       enum ssl_hash_message_t hash_message, int *ok);
int dtls1_dispatch_alert(SSL *ssl);

int ssl_init_wbio_buffer(SSL *ssl, int push);
void ssl_free_wbio_buffer(SSL *ssl);

int tls1_change_cipher_state(SSL *ssl, int which);
int tls1_setup_key_block(SSL *ssl);
int tls1_handshake_digest(SSL *ssl, uint8_t *out, size_t out_len);
int tls1_generate_master_secret(SSL *ssl, uint8_t *out, const uint8_t *premaster,
                                size_t premaster_len);

char ssl_early_callback_init(struct ssl_early_callback_ctx *ctx);

/* tls1_check_curve_id returns one if |curve_id| is consistent with both our
 * and the peer's curve preferences. Note: if called as the client, only our
 * preferences are checked; the peer (the server) does not send preferences. */
int tls1_check_curve_id(SSL *ssl, uint16_t curve_id);

/* tls1_get_shared_curve sets |*out_curve_id| to the first preferred shared
 * curve between client and server preferences and returns one. If none may be
 * found, it returns zero. */
int tls1_get_shared_curve(SSL *ssl, uint16_t *out_curve_id);

/* tls1_set_curves converts the array of |ncurves| NIDs pointed to by |curves|
 * into a newly allocated array of TLS curve IDs. On success, the function
 * returns one and writes the array to |*out_curve_ids| and its size to
 * |*out_curve_ids_len|. Otherwise, it returns zero. */
int tls1_set_curves(uint16_t **out_curve_ids, size_t *out_curve_ids_len,
                    const int *curves, size_t ncurves);

/* tls1_check_ec_cert returns one if |x| is an ECC certificate with curve and
 * point format compatible with the client's preferences. Otherwise it returns
 * zero. */
int tls1_check_ec_cert(SSL *ssl, X509 *x);

/* ssl_add_clienthello_tlsext writes ClientHello extensions to |out|. It
 * returns one on success and zero on failure. The |header_len| argument is the
 * length of the ClientHello written so far and is used to compute the padding
 * length. (It does not include the record header.) */
int ssl_add_clienthello_tlsext(SSL *ssl, CBB *out, size_t header_len);

int ssl_add_serverhello_tlsext(SSL *ssl, CBB *out);
int ssl_parse_clienthello_tlsext(SSL *ssl, CBS *cbs);
int ssl_parse_serverhello_tlsext(SSL *ssl, CBS *cbs);

#define tlsext_tick_md EVP_sha256

/* tls_process_ticket processes a session ticket from the client. On success,
 * it sets |*out_session| to the decrypted session or NULL if the ticket was
 * rejected. If the ticket was valid, it sets |*out_renew_ticket| to whether
 * the ticket should be renewed. It returns one on success and zero on fatal
 * error. */
int tls_process_ticket(SSL *ssl, SSL_SESSION **out_session,
                       int *out_renew_ticket, const uint8_t *ticket,
                       size_t ticket_len, const uint8_t *session_id,
                       size_t session_id_len);

/* tls12_add_sigandhash assembles the SignatureAndHashAlgorithm corresponding to
 * |ssl|'s private key and |md|. The two-byte value is written to |out|. It
 * returns one on success and zero on failure. */
int tls12_add_sigandhash(SSL *ssl, CBB *out, const EVP_MD *md);

int tls12_get_sigid(int pkey_type);
const EVP_MD *tls12_get_hash(uint8_t hash_alg);

/* tls1_channel_id_hash computes the hash to be signed by Channel ID and writes
 * it to |out|, which must contain at least |EVP_MAX_MD_SIZE| bytes. It returns
 * one on success and zero on failure. */
int tls1_channel_id_hash(SSL *ssl, uint8_t *out, size_t *out_len);

int tls1_record_handshake_hashes_for_channel_id(SSL *ssl);

/* ssl_log_rsa_client_key_exchange logs |premaster|, if logging is enabled for
 * |ssl|. It returns one on success and zero on failure. The entry is identified
 * by the first 8 bytes of |encrypted_premaster|. */
int ssl_log_rsa_client_key_exchange(const SSL *ssl,
                                    const uint8_t *encrypted_premaster,
                                    size_t encrypted_premaster_len,
                                    const uint8_t *premaster,
                                    size_t premaster_len);

/* ssl_log_master_secret logs |master|, if logging is enabled for |ssl|. It
 * returns one on success and zero on failure. The entry is identified by
 * |client_random|. */
int ssl_log_master_secret(const SSL *ssl, const uint8_t *client_random,
                          size_t client_random_len, const uint8_t *master,
                          size_t master_len);

/* ssl3_can_false_start returns one if |ssl| is allowed to False Start and zero
 * otherwise. */
int ssl3_can_false_start(const SSL *ssl);

/* ssl3_get_enc_method returns the SSL3_ENC_METHOD corresponding to
 * |version|. */
const SSL3_ENC_METHOD *ssl3_get_enc_method(uint16_t version);

/* ssl3_get_max_server_version returns the maximum SSL/TLS version number
 * supported by |ssl| as a server, or zero if all versions are disabled. */
uint16_t ssl3_get_max_server_version(const SSL *ssl);

/* ssl3_get_mutual_version selects the protocol version on |ssl| for a client
 * which advertises |client_version|. If no suitable version exists, it returns
 * zero. */
uint16_t ssl3_get_mutual_version(SSL *ssl, uint16_t client_version);

/* ssl3_get_max_client_version returns the maximum protocol version configured
 * for the client. It is guaranteed that the set of allowed versions at or below
 * this maximum version is contiguous. If all versions are disabled, it returns
 * zero. */
uint16_t ssl3_get_max_client_version(SSL *ssl);

/* ssl3_is_version_enabled returns one if |version| is an enabled protocol
 * version for |ssl| and zero otherwise. */
int ssl3_is_version_enabled(SSL *ssl, uint16_t version);

/* ssl3_version_from_wire maps |wire_version| to a protocol version. For
 * SSLv3/TLS, the version is returned as-is. For DTLS, the corresponding TLS
 * version is used. Note that this mapping is not injective but preserves
 * comparisons.
 *
 * TODO(davidben): To normalize some DTLS-specific code, move away from using
 * the wire version except at API boundaries. */
uint16_t ssl3_version_from_wire(const SSL *ssl, uint16_t wire_version);

/* ssl3_protocol_version returns |ssl|'s protocol version. It is an error to
 * call this function before the version is determined. */
uint16_t ssl3_protocol_version(const SSL *ssl);

uint32_t ssl_get_algorithm_prf(const SSL *ssl);
int tls1_parse_peer_sigalgs(SSL *ssl, const CBS *sigalgs);

/* tls1_choose_signing_digest returns a digest for use with |ssl|'s private key
 * based on the peer's preferences the digests supported. */
const EVP_MD *tls1_choose_signing_digest(SSL *ssl);

size_t tls12_get_psigalgs(SSL *ssl, const uint8_t **psigs);

/* tls12_check_peer_sigalg checks that |hash| and |signature| are consistent
 * with |pkey| and |ssl|'s sent, supported signature algorithms and, if so,
 * writes the relevant digest into |*out_md| and returns 1. Otherwise it
 * returns 0 and writes an alert into |*out_alert|. */
int tls12_check_peer_sigalg(SSL *ssl, const EVP_MD **out_md, int *out_alert,
                            uint8_t hash, uint8_t signature, EVP_PKEY *pkey);
void ssl_set_client_disabled(SSL *ssl);

#endif /* OPENSSL_HEADER_SSL_INTERNAL_H */
