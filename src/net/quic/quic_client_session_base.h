// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CLIENT_SESSION_BASE_H_
#define NET_QUIC_QUIC_CLIENT_SESSION_BASE_H_

#include "net/quic/quic_crypto_client_stream.h"
#include "net/quic/quic_session.h"

namespace net {

// Base class for all client-specific QuicSession subclasses.
class NET_EXPORT_PRIVATE QuicClientSessionBase : public QuicSession {
 public:
  QuicClientSessionBase(QuicConnection* connection,
                        const QuicConfig& config);

  ~QuicClientSessionBase() override;

  // Called when the proof in |cached| is marked valid.  If this is a secure
  // QUIC session, then this will happen only after the proof verifier
  // completes.  If this is an insecure QUIC connection, this will happen
  // as soon as a valid config is discovered (either from the cache or
  // from the server).
  virtual void OnProofValid(
      const QuicCryptoClientConfig::CachedState& cached) = 0;

  // Called when proof verification details become available, either because
  // proof verification is complete, or when cached details are used. This
  // will only be called for secure QUIC connections.
  virtual void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) = 0;

  // Override base class to set FEC policy before any data is sent by client.
  void OnCryptoHandshakeEvent(CryptoHandshakeEvent event) override;

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicClientSessionBase);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CLIENT_SESSION_BASE_H_
