// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Some helpers for quic crypto

#ifndef NET_QUIC_CRYPTO_CRYPTO_UTILS_H_
#define NET_QUIC_CRYPTO_CRYPTO_UTILS_H_

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

class QuicTime;
class QuicRandom;
struct QuicCryptoNegotiatedParameters;

class NET_EXPORT_PRIVATE CryptoUtils {
 public:
  // Generates the connection nonce. The nonce is formed as:
  //   <4 bytes> current time
  //   <8 bytes> |orbit| (or random if |orbit| is empty)
  //   <20 bytes> random
  static void GenerateNonce(QuicWallTime now,
                            QuicRandom* random_generator,
                            base::StringPiece orbit,
                            std::string* nonce);

  // Returns true if the sni is valid, false otherwise.
  //  (1) disallow IP addresses;
  //  (2) check that the hostname contains valid characters only; and
  //  (3) contains at least one dot.
  static bool IsValidSNI(base::StringPiece sni);

  // Convert hostname to lowercase and remove the trailing '.'.
  // Returns |hostname|. NormalizeHostname() doesn't support IP address
  // literals. IsValidSNI() should be called before calling NormalizeHostname().
  static std::string NormalizeHostname(const char* hostname);

  // DeriveKeys populates |crypters->encrypter|, |crypters->decrypter|, and
  // |subkey_secret| (optional -- may be null) given the contents of
  // |premaster_secret|, |client_nonce|, |server_nonce| and |hkdf_input|. |aead|
  // determines which cipher will be used. |perspective| controls whether the
  // server's keys are assigned to |encrypter| or |decrypter|. |server_nonce| is
  // optional and, if non-empty, is mixed into the key derivation.
  // |subkey_secret| will have the same length as |premaster_secret|.
  static bool DeriveKeys(base::StringPiece premaster_secret,
                         QuicTag aead,
                         base::StringPiece client_nonce,
                         base::StringPiece server_nonce,
                         const std::string& hkdf_input,
                         Perspective perspective,
                         CrypterPair* crypters,
                         std::string* subkey_secret);

  // Performs key extraction to derive a new secret of |result_len| bytes
  // dependent on |subkey_secret|, |label|, and |context|. Returns false if the
  // parameters are invalid (e.g. |label| contains null bytes); returns true on
  // success.
  static bool ExportKeyingMaterial(base::StringPiece subkey_secret,
                                   base::StringPiece label,
                                   base::StringPiece context,
                                   size_t result_len,
                                   std::string* result);

 private:
  DISALLOW_COPY_AND_ASSIGN(CryptoUtils);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CRYPTO_UTILS_H_
