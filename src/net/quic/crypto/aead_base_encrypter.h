// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_
#define NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_

#include "base/compiler_specific.h"
#include "net/quic/crypto/quic_encrypter.h"

#if defined(USE_OPENSSL)
#include "net/quic/crypto/scoped_evp_aead_ctx.h"
#else
#include <pkcs11t.h>
#include <seccomon.h>
typedef struct PK11SymKeyStr PK11SymKey;
typedef SECStatus (*PK11_EncryptFunction)(
    PK11SymKey* symKey, CK_MECHANISM_TYPE mechanism, SECItem* param,
    unsigned char* out, unsigned int* outLen, unsigned int maxLen,
    const unsigned char* data, unsigned int dataLen);
#endif

namespace net {

// AeadBaseEncrypter is the base class of AEAD QuicEncrypter subclasses.
class NET_EXPORT_PRIVATE AeadBaseEncrypter : public QuicEncrypter {
 public:
#if defined(USE_OPENSSL)
  AeadBaseEncrypter(const EVP_AEAD* aead_alg,
                    size_t key_size,
                    size_t auth_tag_size,
                    size_t nonce_prefix_size);
#else
  AeadBaseEncrypter(CK_MECHANISM_TYPE aead_mechanism,
                    PK11_EncryptFunction pk11_encrypt,
                    size_t key_size,
                    size_t auth_tag_size,
                    size_t nonce_prefix_size);
#endif
  ~AeadBaseEncrypter() override;

  // QuicEncrypter implementation
  bool SetKey(base::StringPiece key) override;
  bool SetNoncePrefix(base::StringPiece nonce_prefix) override;
  bool EncryptPacket(QuicPacketSequenceNumber sequence_number,
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
  // nonce prefix and sequence number.
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

#if !defined(USE_OPENSSL)
  struct AeadParams {
    unsigned int len;
    union {
      CK_GCM_PARAMS gcm_params;
#if !defined(USE_NSS_CERTS)
      // USE_NSS_CERTS implies we are using system NSS rather than our copy of
      // NSS. The system NSS <pkcs11n.h> header doesn't define this type yet.
      CK_NSS_AEAD_PARAMS nss_aead_params;
#endif
    } data;
  };

  virtual void FillAeadParams(base::StringPiece nonce,
                              base::StringPiece associated_data,
                              size_t auth_tag_size,
                              AeadParams* aead_params) const = 0;
#endif

 private:
#if defined(USE_OPENSSL)
  const EVP_AEAD* const aead_alg_;
#else
  const CK_MECHANISM_TYPE aead_mechanism_;
  const PK11_EncryptFunction pk11_encrypt_;
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

  DISALLOW_COPY_AND_ASSIGN(AeadBaseEncrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_AEAD_BASE_ENCRYPTER_H_
