#include <boringssl/bssl.h>
/* Copyright (c) 2015, Google Inc.
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

#ifndef OPENSSL_HEADER_SSL_TEST_SCOPED_TYPES_H
#define OPENSSL_HEADER_SSL_TEST_SCOPED_TYPES_H

#include <boringssl/ssl.h>

#include "../../crypto/test/scoped_types.h"


using ScopedSSL = ScopedOpenSSLType<SSL, SSL_free>;
using ScopedSSL_CTX = ScopedOpenSSLType<SSL_CTX, SSL_CTX_free>;
using ScopedSSL_SESSION = ScopedOpenSSLType<SSL_SESSION, SSL_SESSION_free>;


#endif  // OPENSSL_HEADER_SSL_TEST_SCOPED_TYPES_H
