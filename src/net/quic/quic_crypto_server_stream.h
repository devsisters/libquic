// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CRYPTO_SERVER_STREAM_H_
#define NET_QUIC_QUIC_CRYPTO_SERVER_STREAM_H_

#include <string>

#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/proto/source_address_token.pb.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_crypto_stream.h"

namespace net {

class CachedNetworkParameters;
class CryptoHandshakeMessage;
class QuicCryptoServerConfig;
class QuicCryptoServerStream;
class QuicSession;

namespace test {
class CryptoTestUtils;
class QuicCryptoServerStreamPeer;
}  // namespace test

// Receives a notification when the server hello (SHLO) has been ACKed by the
// peer. At this point we disable HANDSHAKE_MODE in the sent packet manager.
class NET_EXPORT_PRIVATE ServerHelloNotifier : public
    QuicAckNotifier::DelegateInterface {
 public:
  explicit ServerHelloNotifier(QuicCryptoServerStream* stream)
      : server_stream_(stream) {}

  // QuicAckNotifier::DelegateInterface implementation
  void OnAckNotification(int num_retransmitted_packets,
                         int num_retransmitted_bytes,
                         QuicTime::Delta delta_largest_observed) override;

 private:
  ~ServerHelloNotifier() override {}

  QuicCryptoServerStream* server_stream_;

  DISALLOW_COPY_AND_ASSIGN(ServerHelloNotifier);
};

class NET_EXPORT_PRIVATE QuicCryptoServerStream : public QuicCryptoStream {
 public:
  // |crypto_config| must outlive the stream.
  QuicCryptoServerStream(const QuicCryptoServerConfig* crypto_config,
                         QuicSession* session);
  ~QuicCryptoServerStream() override;

  // Cancel any outstanding callbacks, such as asynchronous validation of client
  // hello.
  void CancelOutstandingCallbacks();

  // CryptoFramerVisitorInterface implementation
  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;

  // GetBase64SHA256ClientChannelID sets |*output| to the base64 encoded,
  // SHA-256 hash of the client's ChannelID key and returns true, if the client
  // presented a ChannelID. Otherwise it returns false.
  bool GetBase64SHA256ClientChannelID(std::string* output) const;

  uint8 num_handshake_messages() const { return num_handshake_messages_; }

  uint8 num_handshake_messages_with_server_nonces() const {
    return num_handshake_messages_with_server_nonces_;
  }

  int num_server_config_update_messages_sent() const {
    return num_server_config_update_messages_sent_;
  }

  // Sends the latest server config and source-address token to the client.
  virtual void SendServerConfigUpdate(
      const CachedNetworkParameters* cached_network_params);

  // Called by the ServerHello AckNotifier once the SHLO has been ACKed by the
  // client.
  void OnServerHelloAcked();

  void set_previous_cached_network_params(
      CachedNetworkParameters cached_network_params);

  const CachedNetworkParameters* previous_cached_network_params() const;

  bool use_stateless_rejects_if_peer_supported() const {
    return use_stateless_rejects_if_peer_supported_;
  }

  // Used by the quic dispatcher to indicate that this crypto server
  // stream should use stateless rejects, so long as stateless rejects
  // are supported by the client.
  void set_use_stateless_rejects_if_peer_supported(
      bool use_stateless_rejects_if_peer_supported) {
    use_stateless_rejects_if_peer_supported_ =
        use_stateless_rejects_if_peer_supported;
  }

  bool peer_supports_stateless_rejects() const {
    return peer_supports_stateless_rejects_;
  }

  void set_peer_supports_stateless_rejects(
      bool peer_supports_stateless_rejects) {
    peer_supports_stateless_rejects_ = peer_supports_stateless_rejects;
  }

 protected:
  virtual QuicErrorCode ProcessClientHello(
      const CryptoHandshakeMessage& message,
      const ValidateClientHelloResultCallback::Result& result,
      CryptoHandshakeMessage* reply,
      std::string* error_details);

  // Hook that allows the server to set QuicConfig defaults just
  // before going through the parameter negotiation step.
  virtual void OverrideQuicConfigDefaults(QuicConfig* config);

  // Given the current connection_id, generates a new ConnectionId to
  // be returned with a stateless reject.
  virtual QuicConnectionId GenerateConnectionIdForReject(
      QuicConnectionId connection_id);

 private:
  friend class test::CryptoTestUtils;
  friend class test::QuicCryptoServerStreamPeer;

  class ValidateCallback : public ValidateClientHelloResultCallback {
   public:
    explicit ValidateCallback(QuicCryptoServerStream* parent);
    // To allow the parent to detach itself from the callback before deletion.
    void Cancel();

    // From ValidateClientHelloResultCallback
    void RunImpl(const CryptoHandshakeMessage& client_hello,
                 const Result& result) override;

   private:
    QuicCryptoServerStream* parent_;

    DISALLOW_COPY_AND_ASSIGN(ValidateCallback);
  };

  // Invoked by ValidateCallback::RunImpl once initial validation of
  // the client hello is complete.  Finishes processing of the client
  // hello message and handles handshake success/failure.
  void FinishProcessingHandshakeMessage(
      const CryptoHandshakeMessage& message,
      const ValidateClientHelloResultCallback::Result& result);

  // Checks the options on the handshake-message to see whether the
  // peer supports stateless-rejects.
  static bool DoesPeerSupportStatelessRejects(
      const CryptoHandshakeMessage& message);

  // crypto_config_ contains crypto parameters for the handshake.
  const QuicCryptoServerConfig* crypto_config_;

  // Pointer to the active callback that will receive the result of
  // the client hello validation request and forward it to
  // FinishProcessingHandshakeMessage for processing.  nullptr if no
  // handshake message is being validated.
  ValidateCallback* validate_client_hello_cb_;

  // Number of handshake messages received by this stream.
  uint8 num_handshake_messages_;

  // Number of handshake messages received by this stream that contain
  // server nonces (indicating that this is a non-zero-RTT handshake
  // attempt).
  uint8 num_handshake_messages_with_server_nonces_;

  // Number of server config update (SCUP) messages sent by this stream.
  int num_server_config_update_messages_sent_;

  // If the client provides CachedNetworkParameters in the STK in the CHLO, then
  // store here, and send back in future STKs if we have no better bandwidth
  // estimate to send.
  scoped_ptr<CachedNetworkParameters> previous_cached_network_params_;

  // Contains any source address tokens which were present in the CHLO.
  SourceAddressTokens previous_source_address_tokens_;

  // If true, the server should use stateless rejects, so long as the
  // client supports them, as indicated by
  // peer_supports_stateless_rejects_.
  bool use_stateless_rejects_if_peer_supported_;

  // Set to true, once the server has received information from the
  // client that it supports stateless reject.
  //  TODO(jokulik): Remove once client stateless reject support
  // becomes the default.
  bool peer_supports_stateless_rejects_;

  DISALLOW_COPY_AND_ASSIGN(QuicCryptoServerStream);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CRYPTO_SERVER_STREAM_H_
