// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_KEY_EXCHANGE_H_
#define NET_QUIC_CRYPTO_KEY_EXCHANGE_H_

#include <string>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/crypto_protocol.h"

namespace net {

class QuicRandom;

// KeyExchange is an abstract class that provides an interface to a
// key-exchange primitive.
class NET_EXPORT_PRIVATE KeyExchange {
 public:
  virtual ~KeyExchange() {}

  // NewKeyPair generates a new public, private key pair. The caller takes
  // ownership of the return value. (This is intended for servers that need to
  // generate forward-secure keys.)
  virtual KeyExchange* NewKeyPair(QuicRandom* rand) const = 0;

  // CalculateSharedKey computes the shared key between the local private key
  // (which is implicitly known by a KeyExchange object) and a public value
  // from the peer.
  virtual bool CalculateSharedKey(const base::StringPiece& peer_public_value,
                                  std::string* shared_key) const = 0;

  // public_value returns the local public key which can be sent to a peer in
  // order to complete a key exchange. The returned StringPiece is a reference
  // to a member of the KeyExchange and is only valid for as long as the
  // KeyExchange exists.
  virtual base::StringPiece public_value() const = 0;

  // tag returns the tag value that identifies this key exchange function.
  virtual QuicTag tag() const = 0;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_KEY_EXCHANGE_H_
