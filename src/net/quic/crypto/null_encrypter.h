// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_NULL_ENCRYPTER_H_
#define NET_QUIC_CRYPTO_NULL_ENCRYPTER_H_

#include <stddef.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/quic_encrypter.h"

namespace net {

// A NullEncrypter is a QuicEncrypter used before a crypto negotiation
// has occurred.  It does not actually encrypt the payload, but does
// generate a MAC (fnv128) over both the payload and associated data.
class NET_EXPORT_PRIVATE NullEncrypter : public QuicEncrypter {
 public:
  NullEncrypter();
  ~NullEncrypter() override {}

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

 private:
  size_t GetHashLength() const;

  DISALLOW_COPY_AND_ASSIGN(NullEncrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_NULL_ENCRYPTER_H_
