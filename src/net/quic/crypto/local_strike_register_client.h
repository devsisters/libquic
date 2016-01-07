// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_
#define NET_QUIC_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_

#include <stdint.h>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/strike_register.h"
#include "net/quic/crypto/strike_register_client.h"
#include "net/quic/quic_time.h"

namespace net {

// StrikeRegisterClient implementation that wraps a local in-memory
// strike register.
class NET_EXPORT_PRIVATE LocalStrikeRegisterClient
    : public StrikeRegisterClient {
 public:
  LocalStrikeRegisterClient(unsigned max_entries,
                            uint32_t current_time_external,
                            uint32_t window_secs,
                            const uint8_t orbit[8],
                            StrikeRegister::StartupType startup);

  bool IsKnownOrbit(base::StringPiece orbit) const override;
  void VerifyNonceIsValidAndUnique(base::StringPiece nonce,
                                   QuicWallTime now,
                                   ResultCallback* cb) override;

 private:
  mutable base::Lock m_;
  StrikeRegister strike_register_;

  DISALLOW_COPY_AND_ASSIGN(LocalStrikeRegisterClient);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_LOCAL_STRIKE_REGISTER_CLIENT_H_
