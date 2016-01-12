// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_secret_boxer.h"

#include "base/logging.h"
#include "base/memory/scoped_ptr.h"
#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"
#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_random.h"

using base::StringPiece;
using std::string;

namespace net {

// Defined kKeySize for GetKeySize() and SetKey().
static const size_t kKeySize = 16;

// kBoxNonceSize contains the number of bytes of nonce that we use in each box.
// TODO(rtenneti): Add support for kBoxNonceSize to be 16 bytes.
//
// From agl@:
//   96-bit nonces are on the edge. An attacker who can collect 2^41
//   source-address tokens has a 1% chance of finding a duplicate.
//
//   The "average" DDoS is now 32.4M PPS. That's 2^25 source-address tokens
//   per second. So one day of that DDoS botnot would reach the 1% mark.
//
//   It's not terrible, but it's not a "forget about it" margin.
static const size_t kBoxNonceSize = 12;

// static
size_t CryptoSecretBoxer::GetKeySize() {
  return kKeySize;
}

void CryptoSecretBoxer::SetKey(StringPiece key) {
  DCHECK_EQ(kKeySize, key.size());
  key_ = key.as_string();
}

string CryptoSecretBoxer::Box(QuicRandom* rand, StringPiece plaintext) const {
  scoped_ptr<Aes128Gcm12Encrypter> encrypter(new Aes128Gcm12Encrypter());
  if (!encrypter->SetKey(key_)) {
    DLOG(DFATAL) << "CryptoSecretBoxer's encrypter->SetKey failed.";
    return string();
  }
  size_t ciphertext_size = encrypter->GetCiphertextSize(plaintext.length());

  string ret;
  const size_t len = kBoxNonceSize + ciphertext_size;
  ret.resize(len);
  char* data = &ret[0];

  // Generate nonce.
  rand->RandBytes(data, kBoxNonceSize);
  memcpy(data + kBoxNonceSize, plaintext.data(), plaintext.size());

  if (!encrypter->Encrypt(
          StringPiece(data, kBoxNonceSize), StringPiece(), plaintext,
          reinterpret_cast<unsigned char*>(data + kBoxNonceSize))) {
    DLOG(DFATAL) << "CryptoSecretBoxer's Encrypt failed.";
    return string();
  }

  return ret;
}

bool CryptoSecretBoxer::Unbox(StringPiece ciphertext,
                              string* out_storage,
                              StringPiece* out) const {
  if (ciphertext.size() < kBoxNonceSize) {
    return false;
  }

  StringPiece nonce(ciphertext.data(), kBoxNonceSize);
  ciphertext.remove_prefix(kBoxNonceSize);
  QuicPacketNumber packet_number;
  StringPiece nonce_prefix(nonce.data(), nonce.size() - sizeof(packet_number));
  memcpy(&packet_number, nonce.data() + nonce_prefix.size(),
         sizeof(packet_number));

  scoped_ptr<Aes128Gcm12Decrypter> decrypter(new Aes128Gcm12Decrypter());
  if (!decrypter->SetKey(key_)) {
    DLOG(DFATAL) << "CryptoSecretBoxer's decrypter->SetKey failed.";
    return false;
  }
  decrypter->SetNoncePrefix(nonce_prefix);
  char plaintext[kMaxPacketSize];
  size_t plaintext_length = 0;
  const bool success = decrypter->DecryptPacket(
      packet_number, StringPiece() /* associated data */, ciphertext, plaintext,
      &plaintext_length, kMaxPacketSize);
  if (!success) {
    return false;
  }

  out_storage->resize(plaintext_length);
  out_storage->assign(plaintext, plaintext_length);
  out->set(out_storage->data(), plaintext_length);
  return true;
}

}  // namespace net
