// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "net/quic/crypto/null_decrypter.h"
#include "net/quic/quic_utils.h"
#include "net/quic/quic_data_reader.h"

using base::StringPiece;
using std::string;

namespace net {

NullDecrypter::NullDecrypter() {}

bool NullDecrypter::SetKey(StringPiece key) { return key.empty(); }

bool NullDecrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  return nonce_prefix.empty();
}

bool NullDecrypter::DecryptPacket(QuicPacketSequenceNumber /*seq_number*/,
                                  const StringPiece& associated_data,
                                  const StringPiece& ciphertext,
                                  char* output,
                                  size_t* output_length,
                                  size_t max_output_length) {
  QuicDataReader reader(ciphertext.data(), ciphertext.length());
  uint128 hash;

  if (!ReadHash(&reader, &hash)) {
    return false;
  }

  StringPiece plaintext = reader.ReadRemainingPayload();
  if (plaintext.length() > max_output_length) {
    LOG(DFATAL) << "Output buffer must be larger than the plaintext.";
    return false;
  }
  if (hash != ComputeHash(associated_data, plaintext)) {
    return false;
  }
  // Copy the plaintext to output.
  memcpy(output, plaintext.data(), plaintext.length());
  *output_length = plaintext.length();
  return true;
}

StringPiece NullDecrypter::GetKey() const { return StringPiece(); }

StringPiece NullDecrypter::GetNoncePrefix() const { return StringPiece(); }

bool NullDecrypter::ReadHash(QuicDataReader* reader, uint128* hash) {
  uint64 lo;
  uint32 hi;
  if (!reader->ReadUInt64(&lo) ||
      !reader->ReadUInt32(&hi)) {
    return false;
  }
  *hash = hi;
  *hash <<= 64;
  *hash += lo;
  return true;
}

uint128 NullDecrypter::ComputeHash(const StringPiece& data1,
                                   const StringPiece& data2) const {
  uint128 correct_hash = QuicUtils::FNV1a_128_Hash_Two(
      data1.data(), data1.length(), data2.data(), data2.length());
  uint128 mask(UINT64_C(0x0), UINT64_C(0xffffffff));
  mask <<= 96;
  correct_hash &= ~mask;
  return correct_hash;
}

}  // namespace net
