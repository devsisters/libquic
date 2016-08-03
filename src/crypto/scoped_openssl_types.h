// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_SCOPED_OPENSSL_TYPES_H_
#define CRYPTO_SCOPED_OPENSSL_TYPES_H_

#include <boringssl/bio.h>
#include <boringssl/bn.h>
#include <boringssl/dsa.h>
#include <boringssl/ec.h>
#include <boringssl/ecdsa.h>
#include <boringssl/evp.h>
#include <boringssl/mem.h>
#include <boringssl/rsa.h>
#include <stdint.h>

#include <memory>

namespace crypto {

// Simplistic helper that wraps a call to a deleter function. In a C++11 world,
// this would be std::function<>. An alternative would be to re-use
// base::internal::RunnableAdapter<>, but that's far too heavy weight.
template <typename Type, void (*Destroyer)(Type*)>
struct OpenSSLDestroyer {
  void operator()(Type* ptr) const { Destroyer(ptr); }
};

template <typename PointerType, void (*Destroyer)(PointerType*)>
using ScopedOpenSSL =
    std::unique_ptr<PointerType, OpenSSLDestroyer<PointerType, Destroyer>>;

struct OpenSSLFree {
  void operator()(uint8_t* ptr) const { OPENSSL_free(ptr); }
};

// Several typedefs are provided for crypto-specific primitives, for
// short-hand and prevalence. Note that OpenSSL types related to X.509 are
// intentionally not included, as crypto/ does not generally deal with
// certificates or PKI.
using ScopedBIGNUM = ScopedOpenSSL<BIGNUM, BN_free>;
using ScopedEC_Key = ScopedOpenSSL<EC_KEY, EC_KEY_free>;
using ScopedBIO = ScopedOpenSSL<BIO, BIO_free_all>;
using ScopedDSA = ScopedOpenSSL<DSA, DSA_free>;
using ScopedECDSA_SIG = ScopedOpenSSL<ECDSA_SIG, ECDSA_SIG_free>;
using ScopedEC_GROUP = ScopedOpenSSL<EC_GROUP, EC_GROUP_free>;
using ScopedEC_KEY = ScopedOpenSSL<EC_KEY, EC_KEY_free>;
using ScopedEC_POINT = ScopedOpenSSL<EC_POINT, EC_POINT_free>;
using ScopedEVP_MD_CTX = ScopedOpenSSL<EVP_MD_CTX, EVP_MD_CTX_destroy>;
using ScopedEVP_PKEY = ScopedOpenSSL<EVP_PKEY, EVP_PKEY_free>;
using ScopedEVP_PKEY_CTX = ScopedOpenSSL<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using ScopedRSA = ScopedOpenSSL<RSA, RSA_free>;

// The bytes must have been allocated with OPENSSL_malloc.
using ScopedOpenSSLBytes = std::unique_ptr<uint8_t, OpenSSLFree>;

}  // namespace crypto

#endif  // CRYPTO_SCOPED_OPENSSL_TYPES_H_
