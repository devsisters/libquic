// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/p256_key_exchange.h"

#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/sys_byteorder.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {

namespace {

// Password used by |NewPrivateKey| to encrypt exported EC private keys.
// This is not used to provide any security, but to workaround NSS being
// unwilling to export unencrypted EC keys. Note that SPDY and ChannelID
// use the same approach.
const char kExportPassword[] = "";

// Convert StringPiece to vector of uint8_t.
static vector<uint8_t> StringPieceToVector(StringPiece piece) {
  return vector<uint8_t>(piece.data(), piece.data() + piece.length());
}

}  // namespace

P256KeyExchange::P256KeyExchange(crypto::ECPrivateKey* key_pair,
                                 const uint8_t* public_key)
    : key_pair_(key_pair) {
  memcpy(public_key_, public_key, sizeof(public_key_));
}

P256KeyExchange::~P256KeyExchange() {}

// static
P256KeyExchange* P256KeyExchange::New(StringPiece key) {
  if (key.size() < 2) {
    DVLOG(1) << "Key pair is too small.";
    return nullptr;
  }

  const uint8_t* data = reinterpret_cast<const uint8_t*>(key.data());
  size_t size =
      static_cast<size_t>(data[0]) | (static_cast<size_t>(data[1]) << 8);
  key.remove_prefix(2);
  if (key.size() < size) {
    DVLOG(1) << "Key pair does not contain key material.";
    return nullptr;
  }

  StringPiece private_piece(key.data(), size);
  key.remove_prefix(size);
  if (key.empty()) {
    DVLOG(1) << "Key pair does not contain public key.";
    return nullptr;
  }

  StringPiece public_piece(key);

  scoped_ptr<crypto::ECPrivateKey> key_pair(
      crypto::ECPrivateKey::CreateFromEncryptedPrivateKeyInfo(
          kExportPassword,
          // TODO(thaidn): fix this interface to avoid copying secrets.
          StringPieceToVector(private_piece),
          StringPieceToVector(public_piece)));

  if (!key_pair.get()) {
    DVLOG(1) << "Can't decrypt private key.";
    return nullptr;
  }

  // Perform some sanity checks on the public key.
  SECKEYPublicKey* public_key = key_pair->public_key();
  if (public_key->keyType != ecKey ||
      public_key->u.ec.publicValue.len != kUncompressedP256PointBytes ||
      !public_key->u.ec.publicValue.data ||
      public_key->u.ec.publicValue.data[0] != kUncompressedECPointForm) {
    DVLOG(1) << "Key is invalid.";
    return nullptr;
  }

  // Ensure that the key is using the correct curve, i.e., NIST P-256.
  const SECOidData* oid_data = SECOID_FindOIDByTag(SEC_OID_SECG_EC_SECP256R1);
  if (!oid_data) {
    DVLOG(1) << "Can't get P-256's OID.";
    return nullptr;
  }

  if (public_key->u.ec.DEREncodedParams.len != oid_data->oid.len + 2 ||
      !public_key->u.ec.DEREncodedParams.data ||
      public_key->u.ec.DEREncodedParams.data[0] != SEC_ASN1_OBJECT_ID ||
      public_key->u.ec.DEREncodedParams.data[1] != oid_data->oid.len ||
      memcmp(public_key->u.ec.DEREncodedParams.data + 2, oid_data->oid.data,
             oid_data->oid.len) != 0) {
    DVLOG(1) << "Key is invalid.";
  }

  return new P256KeyExchange(key_pair.release(),
                             public_key->u.ec.publicValue.data);
}

// static
string P256KeyExchange::NewPrivateKey() {
  scoped_ptr<crypto::ECPrivateKey> key_pair(crypto::ECPrivateKey::Create());

  if (!key_pair.get()) {
    DVLOG(1) << "Can't generate new key pair.";
    return string();
  }

  vector<uint8_t> private_key;
  if (!key_pair->ExportEncryptedPrivateKey(kExportPassword, 1 /* iteration */,
                                           &private_key)) {
    DVLOG(1) << "Can't export private key.";
    return string();
  }

  // NSS lacks the ability to import an ECC private key without
  // also importing the public key, so it is necessary to also
  // store the public key.
  vector<uint8_t> public_key;
  if (!key_pair->ExportPublicKey(&public_key)) {
    DVLOG(1) << "Can't export public key.";
    return string();
  }

  // TODO(thaidn): determine how large encrypted private key can be
  uint16_t private_key_size = base::checked_cast<uint16_t>(private_key.size());
  const size_t result_size =
      sizeof(private_key_size) + private_key_size + public_key.size();
  vector<char> result(result_size);
  char* resultp = &result[0];
  // Export the key string.
  // The first two bytes are the private key's size in little endian.
  private_key_size = base::ByteSwapToLE16(private_key_size);
  memcpy(resultp, &private_key_size, sizeof(private_key_size));
  resultp += sizeof(private_key_size);
  memcpy(resultp, &private_key[0], private_key.size());
  resultp += private_key.size();
  memcpy(resultp, &public_key[0], public_key.size());

  return string(&result[0], result_size);
}

KeyExchange* P256KeyExchange::NewKeyPair(QuicRandom* /*rand*/) const {
  // TODO(agl): avoid the serialisation/deserialisation in this function.
  const string private_value = NewPrivateKey();
  return P256KeyExchange::New(private_value);
}

bool P256KeyExchange::CalculateSharedKey(const StringPiece& peer_public_value,
                                         string* out_result) const {
  if (peer_public_value.size() != kUncompressedP256PointBytes ||
      peer_public_value[0] != kUncompressedECPointForm) {
    DVLOG(1) << "Peer public value is invalid.";
    return false;
  }

  DCHECK(key_pair_.get());
  DCHECK(key_pair_->public_key());

  SECKEYPublicKey peer_public_key;
  memset(&peer_public_key, 0, sizeof(peer_public_key));

  peer_public_key.keyType = ecKey;
  // Both sides of a ECDH key exchange need to use the same EC params.
  peer_public_key.u.ec.DEREncodedParams.len =
      key_pair_->public_key()->u.ec.DEREncodedParams.len;
  peer_public_key.u.ec.DEREncodedParams.data =
      key_pair_->public_key()->u.ec.DEREncodedParams.data;

  peer_public_key.u.ec.publicValue.type = siBuffer;
  peer_public_key.u.ec.publicValue.data =
      reinterpret_cast<uint8_t*>(const_cast<char*>(peer_public_value.data()));
  peer_public_key.u.ec.publicValue.len = peer_public_value.size();

  // The NSS function performing ECDH key exchange is PK11_PubDeriveWithKDF.
  // As this function is used for SSL/TLS's ECDH key exchanges it has many
  // arguments, most of which are not required in QUIC.
  // Key derivation function CKD_NULL is used because the return value of
  // |CalculateSharedKey| is the actual ECDH shared key, not any derived keys
  // from it.
  crypto::ScopedPK11SymKey premaster_secret(
      PK11_PubDeriveWithKDF(key_pair_->key(), &peer_public_key, PR_FALSE,
                            nullptr, nullptr, CKM_ECDH1_DERIVE, /* mechanism */
                            CKM_GENERIC_SECRET_KEY_GEN,         /* target */
                            CKA_DERIVE, 0, CKD_NULL,            /* kdf */
                            nullptr, nullptr));

  if (!premaster_secret.get()) {
    DVLOG(1) << "Can't derive ECDH shared key.";
    return false;
  }

  if (PK11_ExtractKeyValue(premaster_secret.get()) != SECSuccess) {
    DVLOG(1) << "Can't extract raw ECDH shared key.";
    return false;
  }

  SECItem* key_data = PK11_GetKeyData(premaster_secret.get());
  if (!key_data || !key_data->data || key_data->len != kP256FieldBytes) {
    DVLOG(1) << "ECDH shared key is invalid.";
    return false;
  }

  out_result->assign(reinterpret_cast<char*>(key_data->data), key_data->len);
  return true;
}

StringPiece P256KeyExchange::public_value() const {
  return StringPiece(reinterpret_cast<const char*>(public_key_),
                     sizeof(public_key_));
}

QuicTag P256KeyExchange::tag() const {
  return kP256;
}

}  // namespace net
