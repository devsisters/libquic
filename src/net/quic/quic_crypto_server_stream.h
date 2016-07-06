// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CRYPTO_SERVER_STREAM_H_
#define NET_QUIC_QUIC_CRYPTO_SERVER_STREAM_H_

#include <cstdint>
#include <memory>
#include <string>

#include "base/macros.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/quic_compressed_certs_cache.h"
#include "net/quic/crypto/quic_crypto_server_config.h"
#include "net/quic/proto/source_address_token.pb.h"
#include "net/quic/quic_config.h"
#include "net/quic/quic_crypto_stream.h"

namespace net {

class CachedNetworkParameters;
class CryptoHandshakeMessage;
class QuicCryptoServerConfig;
class QuicCryptoServerStreamBase;
class QuicServerSessionBase;

namespace test {
class CryptoTestUtils;
class QuicCryptoServerStreamPeer;
}  // namespace test

// Receives a notification when the server hello (SHLO) has been ACKed by the
// peer. At this point we disable HANDSHAKE_MODE in the sent packet manager.
class NET_EXPORT_PRIVATE ServerHelloNotifier : public QuicAckListenerInterface {
 public:
  explicit ServerHelloNotifier(QuicCryptoServerStreamBase* stream)
      : server_stream_(stream) {}

  void OnPacketAcked(int acked_bytes, QuicTime::Delta ack_delay_time) override;

  void OnPacketRetransmitted(int retransmitted_bytes) override;

 private:
  ~ServerHelloNotifier() override {}

  QuicCryptoServerStreamBase* server_stream_;

  DISALLOW_COPY_AND_ASSIGN(ServerHelloNotifier);
};

// TODO(alyssar) see what can be moved out of QuicCryptoServerStream with
// various code and test refactoring.
class NET_EXPORT_PRIVATE QuicCryptoServerStreamBase : public QuicCryptoStream {
 public:
  explicit QuicCryptoServerStreamBase(QuicServerSessionBase* session);
  ~QuicCryptoServerStreamBase() override {}

  // Cancel any outstanding callbacks, such as asynchronous validation of client
  // hello.
  virtual void CancelOutstandingCallbacks() = 0;

  // GetBase64SHA256ClientChannelID sets |*output| to the base64 encoded,
  // SHA-256 hash of the client's ChannelID key and returns true, if the client
  // presented a ChannelID. Otherwise it returns false.
  virtual bool GetBase64SHA256ClientChannelID(std::string* output) const = 0;

  virtual int NumServerConfigUpdateMessagesSent() const = 0;

  // Sends the latest server config and source-address token to the client.
  virtual void SendServerConfigUpdate(
      const CachedNetworkParameters* cached_network_params) = 0;

  // Called by the ServerHello AckNotifier once the SHLO has been ACKed by the
  // client.
  virtual void OnServerHelloAcked() = 0;

  // These are all accessors and setters to their respective counters.
  virtual uint8_t NumHandshakeMessages() const = 0;
  virtual uint8_t NumHandshakeMessagesWithServerNonces() const = 0;
  virtual bool UseStatelessRejectsIfPeerSupported() const = 0;
  virtual bool PeerSupportsStatelessRejects() const = 0;
  virtual void SetPeerSupportsStatelessRejects(bool set) = 0;
  virtual const CachedNetworkParameters* PreviousCachedNetworkParams()
      const = 0;
  virtual void SetPreviousCachedNetworkParams(
      CachedNetworkParameters cached_network_params) = 0;

  // Checks the options on the handshake-message to see whether the
  // peer supports stateless-rejects.
  static bool DoesPeerSupportStatelessRejects(
      const CryptoHandshakeMessage& message);
};

class NET_EXPORT_PRIVATE QuicCryptoServerStream
    : public QuicCryptoServerStreamBase {
 public:
  // |crypto_config| must outlive the stream.
  QuicCryptoServerStream(const QuicCryptoServerConfig* crypto_config,
                         QuicCompressedCertsCache* compressed_certs_cache,
                         bool use_stateless_rejects_if_peer_supported,
                         QuicServerSessionBase* session);
  ~QuicCryptoServerStream() override;

  // From QuicCryptoServerStreamBase
  void CancelOutstandingCallbacks() override;
  void OnHandshakeMessage(const CryptoHandshakeMessage& message) override;
  bool GetBase64SHA256ClientChannelID(std::string* output) const override;
  void SendServerConfigUpdate(
      const CachedNetworkParameters* cached_network_params) override;
  void OnServerHelloAcked() override;
  uint8_t NumHandshakeMessages() const override;
  uint8_t NumHandshakeMessagesWithServerNonces() const override;
  int NumServerConfigUpdateMessagesSent() const override;
  const CachedNetworkParameters* PreviousCachedNetworkParams() const override;
  bool UseStatelessRejectsIfPeerSupported() const override;
  bool PeerSupportsStatelessRejects() const override;
  void SetPeerSupportsStatelessRejects(
      bool peer_supports_stateless_rejects) override;
  void SetPreviousCachedNetworkParams(
      CachedNetworkParameters cached_network_params) override;

 protected:
  virtual QuicErrorCode ProcessClientHello(
      const CryptoHandshakeMessage& message,
      const ValidateClientHelloResultCallback::Result& result,
      CryptoHandshakeMessage* reply,
      DiversificationNonce* out_diversification_nonce,
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

  // crypto_config_ contains crypto parameters for the handshake.
  const QuicCryptoServerConfig* crypto_config_;

  // compressed_certs_cache_ contains a set of most recently compressed certs.
  // Owned by QuicDispatcher.
  QuicCompressedCertsCache* compressed_certs_cache_;

  // Server's certificate chain and signature of the server config, as provided
  // by ProofSource::GetProof.
  QuicCryptoProof crypto_proof_;

  // Hash of the last received CHLO message which can be used for generating
  // server config update messages.
  std::string chlo_hash_;

  // Pointer to the active callback that will receive the result of
  // the client hello validation request and forward it to
  // FinishProcessingHandshakeMessage for processing.  nullptr if no
  // handshake message is being validated.
  ValidateCallback* validate_client_hello_cb_;

  // Number of handshake messages received by this stream.
  uint8_t num_handshake_messages_;

  // Number of handshake messages received by this stream that contain
  // server nonces (indicating that this is a non-zero-RTT handshake
  // attempt).
  uint8_t num_handshake_messages_with_server_nonces_;

  // Number of server config update (SCUP) messages sent by this stream.
  int num_server_config_update_messages_sent_;

  // If the client provides CachedNetworkParameters in the STK in the CHLO, then
  // store here, and send back in future STKs if we have no better bandwidth
  // estimate to send.
  std::unique_ptr<CachedNetworkParameters> previous_cached_network_params_;

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
