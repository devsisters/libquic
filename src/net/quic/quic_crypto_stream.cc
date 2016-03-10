// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_crypto_stream.h"

#include <string>

#include "base/strings/string_piece.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_utils.h"
#include "net/quic/quic_connection.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_utils.h"

using std::string;
using base::StringPiece;
using net::SpdyPriority;

namespace net {

#define ENDPOINT                                                               \
  (session()->perspective() == Perspective::IS_SERVER ? "Server: " : "Client:" \
                                                                     " ")

QuicCryptoStream::QuicCryptoStream(QuicSession* session)
    : ReliableQuicStream(kCryptoStreamId, session),
      encryption_established_(false),
      handshake_confirmed_(false) {
  crypto_framer_.set_visitor(this);
  // The crypto stream is exempt from connection level flow control.
  DisableConnectionFlowControlForThisStream();
}

void QuicCryptoStream::OnError(CryptoFramer* framer) {
  DLOG(WARNING) << "Error processing crypto data: "
                << QuicUtils::ErrorToString(framer->error());
}

void QuicCryptoStream::OnHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  DVLOG(1) << ENDPOINT << "Received " << message.DebugString();
  session()->OnCryptoHandshakeMessageReceived(message);
}

void QuicCryptoStream::OnDataAvailable() {
  struct iovec iov;
  while (true) {
    if (sequencer()->GetReadableRegions(&iov, 1) != 1) {
      // No more data to read.
      break;
    }
    StringPiece data(static_cast<char*>(iov.iov_base), iov.iov_len);
    if (!crypto_framer_.ProcessInput(data)) {
      CloseConnectionWithDetails(crypto_framer_.error(),
                                 crypto_framer_.error_detail());
      return;
    }
    sequencer()->MarkConsumed(iov.iov_len);
  }
}

void QuicCryptoStream::SendHandshakeMessage(
    const CryptoHandshakeMessage& message) {
  SendHandshakeMessage(message, nullptr);
}

void QuicCryptoStream::SendHandshakeMessage(
    const CryptoHandshakeMessage& message,
    QuicAckListenerInterface* listener) {
  DVLOG(1) << ENDPOINT << "Sending " << message.DebugString();
  session()->OnCryptoHandshakeMessageSent(message);
  const QuicData& data = message.GetSerialized();
  // TODO(wtc): check the return value.
  WriteOrBufferData(string(data.data(), data.length()), false, listener);
}

bool QuicCryptoStream::ExportKeyingMaterial(StringPiece label,
                                            StringPiece context,
                                            size_t result_len,
                                            string* result) const {
  if (!handshake_confirmed()) {
    DLOG(ERROR) << "ExportKeyingMaterial was called before forward-secure"
                << "encryption was established.";
    return false;
  }
  return CryptoUtils::ExportKeyingMaterial(
      crypto_negotiated_params_.subkey_secret, label, context, result_len,
      result);
}

bool QuicCryptoStream::ExportTokenBindingKeyingMaterial(string* result) const {
  if (!encryption_established()) {
    QUIC_BUG << "ExportTokenBindingKeyingMaterial was called before initial"
             << "encryption was established.";
    return false;
  }
  if (!FLAGS_quic_save_initial_subkey_secret) {
    return false;
  }
  return CryptoUtils::ExportKeyingMaterial(
      crypto_negotiated_params_.initial_subkey_secret, "EXPORTER-Token-Binding",
      /* context= */ "", 32, result);
}

const QuicCryptoNegotiatedParameters&
QuicCryptoStream::crypto_negotiated_params() const {
  return crypto_negotiated_params_;
}

}  // namespace net
