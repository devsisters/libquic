// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_NULL_DECRYPTER_H_
#define NET_QUIC_CRYPTO_NULL_DECRYPTER_H_

#include <stddef.h>
#include <stdint.h>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/quic_decrypter.h"

namespace net {

class QuicDataReader;

// A NullDecrypter is a QuicDecrypter used before a crypto negotiation
// has occurred.  It does not actually decrypt the payload, but does
// verify a hash (fnv128) over both the payload and associated data.
class NET_EXPORT_PRIVATE NullDecrypter : public QuicDecrypter {
 public:
  NullDecrypter();
  ~NullDecrypter() override {}

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

  const char* cipher_name() const override;
  uint32_t cipher_id() const override;

 private:
  bool ReadHash(QuicDataReader* reader, uint128* hash);
  uint128 ComputeHash(const base::StringPiece data1,
                      const base::StringPiece data2) const;

  DISALLOW_COPY_AND_ASSIGN(NullDecrypter);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_NULL_DECRYPTER_H_
