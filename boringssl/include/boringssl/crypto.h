#include <boringssl/bssl.h>
/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#ifndef OPENSSL_HEADER_CRYPTO_H
#define OPENSSL_HEADER_CRYPTO_H

#include <boringssl/base.h>

/* Upstream OpenSSL defines |OPENSSL_malloc|, etc., in crypto.h rather than
 * mem.h. */
#include <boringssl/mem.h>

/* Upstream OpenSSL defines |CRYPTO_LOCK|, etc., in crypto.h rather than
 * thread.h. */
#include <boringssl/thread.h>


#if defined(__cplusplus)
extern "C" {
#endif


/* crypto.h contains functions for initializing the crypto library. */


/* CRYPTO_library_init initializes the crypto library. It must be called if the
 * library is built with BORINGSSL_NO_STATIC_INITIALIZER. Otherwise, it does
 * nothing and a static initializer is used instead. It is safe to call this
 * function multiple times and concurrently from multiple threads.
 *
 * On some ARM configurations, this function may require filesystem access and
 * should be called before entering a sandbox. */
OPENSSL_EXPORT void CRYPTO_library_init(void);


/* Deprecated functions. */

/* OPENSSL_VERSION_TEXT contains a string the identifies the version of
 * “OpenSSL”. node.js requires a version number in this text. */
#define OPENSSL_VERSION_TEXT "OpenSSL 1.0.2 (compatible; BoringSSL)"

#define SSLEAY_VERSION 0

/* SSLeay_version is a compatibility function that returns the string
 * "BoringSSL". */
OPENSSL_EXPORT const char *SSLeay_version(int unused);

/* SSLeay is a compatibility function that returns OPENSSL_VERSION_NUMBER from
 * base.h. */
OPENSSL_EXPORT unsigned long SSLeay(void);

/* CRYPTO_malloc_init returns one. */
OPENSSL_EXPORT int CRYPTO_malloc_init(void);

/* ENGINE_load_builtin_engines does nothing. */
OPENSSL_EXPORT void ENGINE_load_builtin_engines(void);

/* OPENSSL_load_builtin_modules does nothing. */
OPENSSL_EXPORT void OPENSSL_load_builtin_modules(void);

/* FIPS_mode returns zero. */
OPENSSL_EXPORT int FIPS_mode(void);


#if defined(__cplusplus)
}  /* extern C */
#endif

#endif  /* OPENSSL_HEADER_CRYPTO_H */
