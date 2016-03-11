// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_AEAD_BASE_DECRYPTER_H_
#define NET_QUIC_CRYPTO_AEAD_BASE_DECRYPTER_H_

#include <stddef.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/quic/crypto/quic_decrypter.h"

#if defined(USE_OPENSSL)
#include "net/quic/crypto/scoped_evp_aead_ctx.h"
#else
#include <pkcs11t.h>
#endif

namespace net {

// AeadBaseDecrypter is the base class of AEAD QuicDecrypter subclasses.
class NET_EXPORT_PRIVATE AeadBaseDecrypter : public QuicDecrypter {
 public:
#if defined(USE_OPENSSL)
  AeadBaseDecrypter(const EVP_AEAD* aead_alg,
                    size_t key_size,
                    size_t auth_tag_size,
                    size_t nonce_prefix_size);
#else
  AeadBaseDecrypter(CK_MECHANISM_TYPE aead_mechanism,
                    size_t key_size,
                    size_t auth_tag_size,
                    size_t nonce_prefix_size);
#endif
  ~AeadBaseDecrypter() override;

  // QuicDecrypter implementation
  bool SetKey(base::StringPiece key) override;
  bool SetNoncePrefix(base::StringPiece nonce_prefix) override;
  bool DecryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     const base::StringPiece& associated_data,
                     const base::StringPiece& ciphertext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override;
  base::StringPiece GetKey() const override;
  base::StringPiece GetNoncePrefix() const override;

 protected:
  // Make these constants available to the subclasses so that the subclasses
  // can assert at compile time their key_size_ and nonce_prefix_size_ do not
  // exceed the maximum.
  static const size_t kMaxKeySize = 32;
  static const size_t kMaxNoncePrefixSize = 4;

#if !defined(USE_OPENSSL)
  struct AeadParams {
    unsigned int len;
    union {
      CK_GCM_PARAMS gcm_params;
      CK_NSS_AEAD_PARAMS nss_aead_params;
    } data;
  };

  virtual void FillAeadParams(base::StringPiece nonce,
                              const base::StringPiece& associated_data,
                              size_t auth_tag_size,
                              AeadParams* aead_params) const = 0;
#endif  // !defined(USE_OPENSSL)

 private:
#if defined(USE_OPENSSL)
  const EVP_AEAD* const aead_alg_;
#else
  const CK_MECHANISM_TYPE aead_mechanism_;
#endif
  const size_t key_size_;
  const size_t auth_tag_size_;
  const size_t nonce_prefix_size_;

  // The key.
  unsigned char key_[kMaxKeySize];
  // The nonce prefix.
  unsigned char nonce_prefix_[kMaxNoncePrefixSize];

#if defined(USE_OPENSSL)
  ScopedEVPAEADCtx ctx_;
#endif

  DISALLOW_COPY_AND_ASSIGN(AeadBaseDecrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_AEAD_BASE_DECRYPTER_H_
