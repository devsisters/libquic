// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/channel_id.h"

#include <keythi.h>
#include <pk11pub.h>
#include <sechash.h>

using base::StringPiece;

namespace net {

// static
bool ChannelIDVerifier::Verify(StringPiece key,
                               StringPiece signed_data,
                               StringPiece signature) {
  return VerifyRaw(key, signed_data, signature, true);
}

// static
bool ChannelIDVerifier::VerifyRaw(StringPiece key,
                                  StringPiece signed_data,
                                  StringPiece signature,
                                  bool is_channel_id_signature) {
  if (key.size() != 32 * 2 || signature.size() != 32 * 2) {
    return false;
  }

  SECKEYPublicKey public_key;
  memset(&public_key, 0, sizeof(public_key));

  // DER encoding of the object identifier (OID) of the named curve P-256
  // (1.2.840.10045.3.1.7). See RFC 6637 Section 11.
  static const unsigned char p256_oid[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                           0xce, 0x3d, 0x03, 0x01, 0x07};
  public_key.keyType = ecKey;
  public_key.u.ec.DEREncodedParams.type = siBuffer;
  public_key.u.ec.DEREncodedParams.data = const_cast<unsigned char*>(p256_oid);
  public_key.u.ec.DEREncodedParams.len = sizeof(p256_oid);

  unsigned char key_buf[65];
  key_buf[0] = 0x04;
  memcpy(&key_buf[1], key.data(), key.size());
  public_key.u.ec.publicValue.type = siBuffer;
  public_key.u.ec.publicValue.data = key_buf;
  public_key.u.ec.publicValue.len = sizeof(key_buf);

  SECItem signature_item = {siBuffer, reinterpret_cast<unsigned char*>(
                                          const_cast<char*>(signature.data())),
                            static_cast<unsigned int>(signature.size())};

  unsigned char hash_buf[SHA256_LENGTH];
  SECItem hash_item = {siBuffer, hash_buf, sizeof(hash_buf)};

  HASHContext* sha256 = HASH_Create(HASH_AlgSHA256);
  if (!sha256) {
    return false;
  }
  HASH_Begin(sha256);
  if (is_channel_id_signature) {
    HASH_Update(sha256, reinterpret_cast<const unsigned char*>(kContextStr),
                strlen(kContextStr) + 1);
    HASH_Update(sha256,
                reinterpret_cast<const unsigned char*>(kClientToServerStr),
                strlen(kClientToServerStr) + 1);
  }
  HASH_Update(sha256,
              reinterpret_cast<const unsigned char*>(signed_data.data()),
              signed_data.size());
  HASH_End(sha256, hash_buf, &hash_item.len, sizeof(hash_buf));
  HASH_Destroy(sha256);

  return PK11_Verify(&public_key, &signature_item, &hash_item, nullptr) ==
         SECSuccess;
}

}  // namespace net
