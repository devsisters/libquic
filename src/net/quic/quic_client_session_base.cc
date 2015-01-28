// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_client_session_base.h"

#include "net/quic/quic_flags.h"

namespace net {

QuicClientSessionBase::QuicClientSessionBase(
    QuicConnection* connection,
    const QuicConfig& config)
    : QuicSession(connection, config) {}

QuicClientSessionBase::~QuicClientSessionBase() {}

void QuicClientSessionBase::OnCryptoHandshakeEvent(CryptoHandshakeEvent event) {
  QuicSession::OnCryptoHandshakeEvent(event);
  // Set FEC policy for streams immediately after sending CHLO and before any
  // more data is sent.
  if (!FLAGS_enable_quic_fec ||
      event != ENCRYPTION_FIRST_ESTABLISHED ||
      !config()->HasSendConnectionOptions() ||
      !ContainsQuicTag(config()->SendConnectionOptions(), kFHDR)) {
    return;
  }
  // kFHDR config maps to FEC protection always for headers stream.
  // TODO(jri): Add crypto stream in addition to headers for kHDR.
  headers_stream_->set_fec_policy(FEC_PROTECT_ALWAYS);
}

}  // namespace net
