// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_
#define NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_

#include <stddef.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/scoped_evp_aead_ctx.h"

namespace net {

// AeadBaseEncrypter is the base class of AEAD QuicEncrypter subclasses.
class NET_EXPORT_PRIVATE AeadBaseEncrypter : public QuicEncrypter {
 public:
  AeadBaseEncrypter(const EVP_AEAD* aead_alg,
                    size_t key_size,
                    size_t auth_tag_size,
                    size_t nonce_prefix_size);
  ~AeadBaseEncrypter() override;

  // QuicEncrypter implementation
  bool SetKey(base::StringPiece key) override;
  bool SetNoncePrefix(base::StringPiece nonce_prefix) override;
  bool EncryptPacket(QuicPathId path_id,
                     QuicPacketNumber packet_number,
                     base::StringPiece associated_data,
                     base::StringPiece plaintext,
                     char* output,
                     size_t* output_length,
                     size_t max_output_length) override;
  size_t GetKeySize() const override;
  size_t GetNoncePrefixSize() const override;
  size_t GetMaxPlaintextSize(size_t ciphertext_size) const override;
  size_t GetCiphertextSize(size_t plaintext_size) const override;
  base::StringPiece GetKey() const override;
  base::StringPiece GetNoncePrefix() const override;

  // Necessary so unit tests can explicitly specify a nonce, instead of a
  // nonce prefix and packet number.
  bool Encrypt(base::StringPiece nonce,
               base::StringPiece associated_data,
               base::StringPiece plaintext,
               unsigned char* output);

 protected:
  // Make these constants available to the subclasses so that the subclasses
  // can assert at compile time their key_size_ and nonce_prefix_size_ do not
  // exceed the maximum.
  static const size_t kMaxKeySize = 32;
  static const size_t kMaxNoncePrefixSize = 4;

 private:
  const EVP_AEAD* const aead_alg_;
  const size_t key_size_;
  const size_t auth_tag_size_;
  const size_t nonce_prefix_size_;

  // The key.
  unsigned char key_[kMaxKeySize];
  // The nonce prefix.
  unsigned char nonce_prefix_[kMaxNoncePrefixSize];

  ScopedEVPAEADCtx ctx_;

  DISALLOW_COPY_AND_ASSIGN(AeadBaseEncrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_
