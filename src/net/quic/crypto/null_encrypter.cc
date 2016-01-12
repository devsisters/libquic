// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/null_encrypter.h"

#include "net/quic/quic_data_writer.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using std::string;

namespace net {

const size_t kHashSizeShort = 12;  // size of uint128 serialized short

NullEncrypter::NullEncrypter() {}

bool NullEncrypter::SetKey(StringPiece key) {
  return key.empty();
}

bool NullEncrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  return nonce_prefix.empty();
}

bool NullEncrypter::EncryptPacket(QuicPacketNumber /*packet_number*/,
                                  StringPiece associated_data,
                                  StringPiece plaintext,
                                  char* output,
                                  size_t* output_length,
                                  size_t max_output_length) {
  const size_t len = plaintext.size() + GetHashLength();
  if (max_output_length < len) {
    return false;
  }
  uint128 hash = QuicUtils::FNV1a_128_Hash_Two(
      associated_data.data(), associated_data.size(), plaintext.data(),
      plaintext.size());
  // TODO(ianswett): memmove required for in place encryption.  Placing the
  // hash at the end would allow use of memcpy, doing nothing for in place.
  memmove(output + GetHashLength(), plaintext.data(), plaintext.length());
  QuicUtils::SerializeUint128Short(hash,
                                   reinterpret_cast<unsigned char*>(output));
  *output_length = len;
  return true;
}

size_t NullEncrypter::GetKeySize() const {
  return 0;
}

size_t NullEncrypter::GetNoncePrefixSize() const {
  return 0;
}

size_t NullEncrypter::GetMaxPlaintextSize(size_t ciphertext_size) const {
  return ciphertext_size - GetHashLength();
}

size_t NullEncrypter::GetCiphertextSize(size_t plaintext_size) const {
  return plaintext_size + GetHashLength();
}

StringPiece NullEncrypter::GetKey() const {
  return StringPiece();
}

StringPiece NullEncrypter::GetNoncePrefix() const {
  return StringPiece();
}

size_t NullEncrypter::GetHashLength() const {
  return kHashSizeShort;
}

}  // namespace net
