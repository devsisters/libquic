// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aead_base_encrypter.h"

#include <pk11pub.h>

#include "base/memory/scoped_ptr.h"
#include "crypto/scoped_nss_types.h"

using base::StringPiece;

namespace net {

namespace {

// The maximum size in bytes of the nonce, including 8 bytes of sequence number.
// ChaCha20 uses only the 8 byte sequence number and AES-GCM uses 12 bytes.
const size_t kMaxNonceSize = 12;

}  // namespace

AeadBaseEncrypter::AeadBaseEncrypter(CK_MECHANISM_TYPE aead_mechanism,
                                     size_t key_size,
                                     size_t auth_tag_size,
                                     size_t nonce_prefix_size)
    : aead_mechanism_(aead_mechanism),
      key_size_(key_size),
      auth_tag_size_(auth_tag_size),
      nonce_prefix_size_(nonce_prefix_size) {
  DCHECK_LE(key_size_, sizeof(key_));
  DCHECK_LE(nonce_prefix_size_, sizeof(nonce_prefix_));
  DCHECK_GE(kMaxNonceSize, nonce_prefix_size_);
}

AeadBaseEncrypter::~AeadBaseEncrypter() {}

bool AeadBaseEncrypter::SetKey(StringPiece key) {
  DCHECK_EQ(key.size(), key_size_);
  if (key.size() != key_size_) {
    return false;
  }
  memcpy(key_, key.data(), key.size());
  return true;
}

bool AeadBaseEncrypter::SetNoncePrefix(StringPiece nonce_prefix) {
  DCHECK_EQ(nonce_prefix.size(), nonce_prefix_size_);
  if (nonce_prefix.size() != nonce_prefix_size_) {
    return false;
  }
  memcpy(nonce_prefix_, nonce_prefix.data(), nonce_prefix.size());
  return true;
}

bool AeadBaseEncrypter::Encrypt(StringPiece nonce,
                                StringPiece associated_data,
                                StringPiece plaintext,
                                unsigned char* output) {
  if (nonce.size() != nonce_prefix_size_ + sizeof(QuicPacketNumber)) {
    return false;
  }

  size_t ciphertext_size = GetCiphertextSize(plaintext.length());

  // Import key_ into NSS.
  SECItem key_item;
  key_item.type = siBuffer;
  key_item.data = key_;
  key_item.len = key_size_;
  PK11SlotInfo* slot = PK11_GetInternalSlot();

  // The exact value of the |origin| argument doesn't matter to NSS as long as
  // it's not PK11_OriginFortezzaHack, so we pass PK11_OriginUnwrap as a
  // placeholder.
  crypto::ScopedPK11SymKey aead_key(
      PK11_ImportSymKey(slot, aead_mechanism_, PK11_OriginUnwrap, CKA_ENCRYPT,
                        &key_item, nullptr));
  PK11_FreeSlot(slot);
  slot = nullptr;
  if (!aead_key) {
    DVLOG(1) << "PK11_ImportSymKey failed";
    return false;
  }

  AeadParams aead_params = {0};
  FillAeadParams(nonce, associated_data, auth_tag_size_, &aead_params);

  SECItem param;
  param.type = siBuffer;
  param.data = reinterpret_cast<unsigned char*>(&aead_params.data);
  param.len = aead_params.len;

  if (plaintext.size() > kMaxPacketSize) {
    DLOG(FATAL) << "Plaintext too large";
    return false;
  }
  // NSS doesn't support inplace encryption, so copy plaintext to a temporary
  // buffer.
  unsigned char temp_plaintext[kMaxPacketSize];
  memcpy(temp_plaintext, plaintext.data(), plaintext.size());

  unsigned int output_len;
  if (PK11_Encrypt(aead_key.get(), aead_mechanism_, &param, output, &output_len,
                   ciphertext_size, temp_plaintext,
                   plaintext.size()) != SECSuccess) {
    DVLOG(1) << "PK11_Encrypt failed";
    return false;
  }

  if (output_len != ciphertext_size) {
    DVLOG(1) << "Wrong output length";
    return false;
  }

  return true;
}

bool AeadBaseEncrypter::EncryptPacket(QuicPacketNumber packet_number,
                                      StringPiece associated_data,
                                      StringPiece plaintext,
                                      char* output,
                                      size_t* output_length,
                                      size_t max_output_length) {
  size_t ciphertext_size = GetCiphertextSize(plaintext.length());
  if (max_output_length < ciphertext_size) {
    return false;
  }
  // TODO(ianswett): Introduce a check to ensure that we don't encrypt with the
  // same packet number twice.
  const size_t nonce_size = nonce_prefix_size_ + sizeof(packet_number);
  ALIGNAS(4) char nonce_buffer[kMaxNonceSize];
  memcpy(nonce_buffer, nonce_prefix_, nonce_prefix_size_);
  memcpy(nonce_buffer + nonce_prefix_size_, &packet_number,
         sizeof(packet_number));
  if (!Encrypt(StringPiece(nonce_buffer, nonce_size), associated_data,
               plaintext, reinterpret_cast<unsigned char*>(output))) {
    return false;
  }
  *output_length = ciphertext_size;
  return true;
}

size_t AeadBaseEncrypter::GetKeySize() const {
  return key_size_;
}

size_t AeadBaseEncrypter::GetNoncePrefixSize() const {
  return nonce_prefix_size_;
}

size_t AeadBaseEncrypter::GetMaxPlaintextSize(size_t ciphertext_size) const {
  return ciphertext_size - auth_tag_size_;
}

size_t AeadBaseEncrypter::GetCiphertextSize(size_t plaintext_size) const {
  return plaintext_size + auth_tag_size_;
}

StringPiece AeadBaseEncrypter::GetKey() const {
  return StringPiece(reinterpret_cast<const char*>(key_), key_size_);
}

StringPiece AeadBaseEncrypter::GetNoncePrefix() const {
  if (nonce_prefix_size_ == 0) {
    return StringPiece();
  }
  return StringPiece(reinterpret_cast<const char*>(nonce_prefix_),
                     nonce_prefix_size_);
}

}  // namespace net
