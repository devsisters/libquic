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

#ifndef OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
#define OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H

#include <stdint.h>
#include <stdio.h>

#include <memory>

#include <boringssl/aead.h>
#include <boringssl/asn1.h>
#include <boringssl/bio.h>
#include <boringssl/bn.h>
#include <boringssl/bytestring.h>
#include <boringssl/cmac.h>
#include <boringssl/curve25519.h>
#include <boringssl/dh.h>
#include <boringssl/ecdsa.h>
#include <boringssl/ec.h>
#include <boringssl/ec_key.h>
#include <boringssl/evp.h>
#include <boringssl/hmac.h>
#include <boringssl/mem.h>
#include <boringssl/pkcs8.h>
#include <boringssl/rsa.h>
#include <boringssl/stack.h>
#include <boringssl/x509.h>


template<typename T, void (*func)(T*)>
struct OpenSSLDeleter {
  void operator()(T *obj) {
    func(obj);
  }
};

template<typename StackType, typename T, void (*func)(T*)>
struct OpenSSLStackDeleter {
  void operator()(StackType *obj) {
    sk_pop_free(reinterpret_cast<_STACK*>(obj),
                reinterpret_cast<void (*)(void *)>(func));
  }
};

template<typename T>
struct OpenSSLFree {
  void operator()(T *buf) {
    OPENSSL_free(buf);
  }
};

struct FileCloser {
  void operator()(FILE *file) {
    fclose(file);
  }
};

template<typename T, void (*func)(T*)>
using ScopedOpenSSLType = std::unique_ptr<T, OpenSSLDeleter<T, func>>;

template<typename StackType, typename T, void (*func)(T*)>
using ScopedOpenSSLStack =
    std::unique_ptr<StackType, OpenSSLStackDeleter<StackType, T, func>>;

template<typename T, typename CleanupRet, void (*init_func)(T*),
         CleanupRet (*cleanup_func)(T*)>
class ScopedOpenSSLContext {
 public:
  ScopedOpenSSLContext() {
    init_func(&ctx_);
  }
  ~ScopedOpenSSLContext() {
    cleanup_func(&ctx_);
  }

  T *get() { return &ctx_; }
  const T *get() const { return &ctx_; }

  void Reset() {
    cleanup_func(&ctx_);
    init_func(&ctx_);
  }

 private:
  T ctx_;
};

using ScopedASN1_TYPE = ScopedOpenSSLType<ASN1_TYPE, ASN1_TYPE_free>;
using ScopedBIO = ScopedOpenSSLType<BIO, BIO_vfree>;
using ScopedBIGNUM = ScopedOpenSSLType<BIGNUM, BN_free>;
using ScopedBN_CTX = ScopedOpenSSLType<BN_CTX, BN_CTX_free>;
using ScopedBN_MONT_CTX = ScopedOpenSSLType<BN_MONT_CTX, BN_MONT_CTX_free>;
using ScopedCMAC_CTX = ScopedOpenSSLType<CMAC_CTX, CMAC_CTX_free>;
using ScopedDH = ScopedOpenSSLType<DH, DH_free>;
using ScopedECDSA_SIG = ScopedOpenSSLType<ECDSA_SIG, ECDSA_SIG_free>;
using ScopedEC_GROUP = ScopedOpenSSLType<EC_GROUP, EC_GROUP_free>;
using ScopedEC_KEY = ScopedOpenSSLType<EC_KEY, EC_KEY_free>;
using ScopedEC_POINT = ScopedOpenSSLType<EC_POINT, EC_POINT_free>;
using ScopedEVP_PKEY = ScopedOpenSSLType<EVP_PKEY, EVP_PKEY_free>;
using ScopedEVP_PKEY_CTX = ScopedOpenSSLType<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using ScopedPKCS8_PRIV_KEY_INFO = ScopedOpenSSLType<PKCS8_PRIV_KEY_INFO,
                                                    PKCS8_PRIV_KEY_INFO_free>;
using ScopedPKCS12 = ScopedOpenSSLType<PKCS12, PKCS12_free>;
using ScopedSPAKE2_CTX = ScopedOpenSSLType<SPAKE2_CTX, SPAKE2_CTX_free>;
using ScopedRSA = ScopedOpenSSLType<RSA, RSA_free>;
using ScopedX509 = ScopedOpenSSLType<X509, X509_free>;
using ScopedX509_ALGOR = ScopedOpenSSLType<X509_ALGOR, X509_ALGOR_free>;
using ScopedX509_SIG = ScopedOpenSSLType<X509_SIG, X509_SIG_free>;
using ScopedX509_STORE_CTX = ScopedOpenSSLType<X509_STORE_CTX, X509_STORE_CTX_free>;

using ScopedX509Stack = ScopedOpenSSLStack<STACK_OF(X509), X509, X509_free>;

using ScopedCBB = ScopedOpenSSLContext<CBB, void, CBB_zero, CBB_cleanup>;
using ScopedEVP_AEAD_CTX = ScopedOpenSSLContext<EVP_AEAD_CTX, void,
                                                EVP_AEAD_CTX_zero,
                                                EVP_AEAD_CTX_cleanup>;
using ScopedEVP_CIPHER_CTX = ScopedOpenSSLContext<EVP_CIPHER_CTX, int,
                                                  EVP_CIPHER_CTX_init,
                                                  EVP_CIPHER_CTX_cleanup>;
using ScopedEVP_MD_CTX = ScopedOpenSSLContext<EVP_MD_CTX, int, EVP_MD_CTX_init,
                                              EVP_MD_CTX_cleanup>;
using ScopedHMAC_CTX = ScopedOpenSSLContext<HMAC_CTX, void, HMAC_CTX_init,
                                            HMAC_CTX_cleanup>;

using ScopedOpenSSLBytes = std::unique_ptr<uint8_t, OpenSSLFree<uint8_t>>;
using ScopedOpenSSLString = std::unique_ptr<char, OpenSSLFree<char>>;

using ScopedFILE = std::unique_ptr<FILE, FileCloser>;

#endif  // OPENSSL_HEADER_CRYPTO_TEST_SCOPED_TYPES_H
