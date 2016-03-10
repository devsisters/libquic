// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aead_base_decrypter.h"

#include <pk11pub.h>

#include "base/memory/scoped_ptr.h"
#include "crypto/scoped_nss_types.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;

namespace net {

AeadBaseDecrypter::AeadBaseDecrypter(CK_MECHANISM_TYPE aead_mechanism,
                                     size_t key_size,
                                     size_t auth_tag_size,
                                     size_t nonce_prefix_size)
    : aead_mechanism_(aead_mechanism),
      key_size_(key_size),
      auth_tag_size_(auth_tag_size),
      nonce_prefix_size_(nonce_prefix_size) {
  DCHECK_LE(key_size_, sizeof(key_));
  DCHECK_LE(nonce_prefix_size_, sizeof(nonce_prefix_));
}

AeadBaseDecrypter::~AeadBaseDecrypter() {}

bool AeadBaseDecrypter::SetKey(StringPiece key) {
  DCHECK_EQ(key.size(), key_size_);
  if (key.size() != key_size_) {
    return false;
  }
  memcpy(key_, key.data(), key.size());
  return true;
}

bool AeadBaseDecrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  DCHECK_EQ(nonce_prefix.size(), nonce_prefix_size_);
  if (nonce_prefix.size() != nonce_prefix_size_) {
    return false;
  }
  memcpy(nonce_prefix_, nonce_prefix.data(), nonce_prefix.size());
  return true;
}

bool AeadBaseDecrypter::DecryptPacket(QuicPathId path_id,
                                      QuicPacketNumber packet_number,
                                      const StringPiece& associated_data,
                                      const StringPiece& ciphertext,
                                      char* output,
                                      size_t* output_length,
                                      size_t max_output_length) {
  if (ciphertext.length() < auth_tag_size_) {
    return false;
  }

  uint8_t nonce[sizeof(nonce_prefix_) + sizeof(packet_number)];
  const size_t nonce_size = nonce_prefix_size_ + sizeof(packet_number);
  DCHECK_LE(nonce_size, sizeof(nonce));
  memcpy(nonce, nonce_prefix_, nonce_prefix_size_);
  if (FLAGS_quic_include_path_id_in_iv) {
    uint64_t path_id_packet_number =
        QuicUtils::PackPathIdAndPacketNumber(path_id, packet_number);
    memcpy(nonce + nonce_prefix_size_, &path_id_packet_number,
           sizeof(path_id_packet_number));
  } else {
    memcpy(nonce + nonce_prefix_size_, &packet_number, sizeof(packet_number));
  }

  // NSS 3.14.x incorrectly requires an output buffer at least as long as
  // the ciphertext (NSS bug
  // https://bugzilla.mozilla.org/show_bug.cgi?id= 853674). Fortunately
  // QuicDecrypter::Decrypt() specifies that |output| must be as long as
  // |ciphertext| on entry.
  size_t plaintext_size = ciphertext.length() - auth_tag_size_;

  // Import key_ into NSS.
  SECItem key_item;
  key_item.type = siBuffer;
  key_item.data = key_;
  key_item.len = key_size_;
  PK11SlotInfo* slot = PK11_GetInternalSlot();

  // The exact value of the |origin| argument doesn't matter to NSS as long as
  // it's not PK11_OriginFortezzaHack, so pass PK11_OriginUnwrap as a
  // placeholder.
  crypto::ScopedPK11SymKey aead_key(
      PK11_ImportSymKey(slot, aead_mechanism_, PK11_OriginUnwrap, CKA_DECRYPT,
                        &key_item, nullptr));
  PK11_FreeSlot(slot);
  slot = nullptr;
  if (!aead_key) {
    DVLOG(1) << "PK11_ImportSymKey failed";
    return false;
  }

  AeadParams aead_params = {0};
  FillAeadParams(StringPiece(reinterpret_cast<char*>(nonce), nonce_size),
                 associated_data, auth_tag_size_, &aead_params);

  SECItem param;
  param.type = siBuffer;
  param.data = reinterpret_cast<unsigned char*>(&aead_params.data);
  param.len = aead_params.len;

  unsigned int output_len;
  if (PK11_Decrypt(aead_key.get(), aead_mechanism_, &param,
                   reinterpret_cast<uint8_t*>(output), &output_len,
                   max_output_length,
                   reinterpret_cast<const unsigned char*>(ciphertext.data()),
                   ciphertext.length()) != SECSuccess) {
    return false;
  }

  if (output_len != plaintext_size) {
    DVLOG(1) << "Wrong output length";
    return false;
  }
  *output_length = output_len;
  return true;
}

StringPiece AeadBaseDecrypter::GetKey() const {
  return StringPiece(reinterpret_cast<const char*>(key_), key_size_);
}

StringPiece AeadBaseDecrypter::GetNoncePrefix() const {
  if (nonce_prefix_size_ == 0) {
    return StringPiece();
  }
  return StringPiece(reinterpret_cast<const char*>(nonce_prefix_),
                     nonce_prefix_size_);
}

}  // namespace net
