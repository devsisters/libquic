// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_CONFIG_H_
#define NET_QUIC_QUIC_CONFIG_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

namespace test {
class QuicConfigPeer;
}  // namespace test

class CryptoHandshakeMessage;

// Describes whether or not a given QuicTag is required or optional in the
// handshake message.
enum QuicConfigPresence {
  // This negotiable value can be absent from the handshake message. Default
  // value is selected as the negotiated value in such a case.
  PRESENCE_OPTIONAL,
  // This negotiable value is required in the handshake message otherwise the
  // Process*Hello function returns an error.
  PRESENCE_REQUIRED,
};

// Whether the CryptoHandshakeMessage is from the client or server.
enum HelloType {
  CLIENT,
  SERVER,
};

// An abstract base class that stores a value that can be sent in CHLO/SHLO
// message. These values can be OPTIONAL or REQUIRED, depending on |presence_|.
class NET_EXPORT_PRIVATE QuicConfigValue {
 public:
  QuicConfigValue(QuicTag tag, QuicConfigPresence presence);
  virtual ~QuicConfigValue();

  // Serialises tag name and value(s) to |out|.
  virtual void ToHandshakeMessage(CryptoHandshakeMessage* out) const = 0;

  // Selects a mutually acceptable value from those offered in |peer_hello|
  // and those defined in the subclass.
  virtual QuicErrorCode ProcessPeerHello(
      const CryptoHandshakeMessage& peer_hello,
      HelloType hello_type,
      std::string* error_details) = 0;

 protected:
  const QuicTag tag_;
  const QuicConfigPresence presence_;
};

class NET_EXPORT_PRIVATE QuicNegotiableValue : public QuicConfigValue {
 public:
  QuicNegotiableValue(QuicTag tag, QuicConfigPresence presence);
  ~QuicNegotiableValue() override;

  bool negotiated() const { return negotiated_; }

 protected:
  void set_negotiated(bool negotiated) { negotiated_ = negotiated; }

 private:
  bool negotiated_;
};

class NET_EXPORT_PRIVATE QuicNegotiableUint32 : public QuicNegotiableValue {
  // TODO(fayang): some negotiated values use uint32 as bool (e.g., silent
  // close). Consider adding a QuicNegotiableBool type.
 public:
  // Default and max values default to 0.
  QuicNegotiableUint32(QuicTag name, QuicConfigPresence presence);
  ~QuicNegotiableUint32() override;

  // Sets the maximum possible value that can be achieved after negotiation and
  // also the default values to be assumed if PRESENCE_OPTIONAL and the *HLO msg
  // doesn't contain a value corresponding to |name_|. |max| is serialised via
  // ToHandshakeMessage call if |negotiated_| is false.
  void set(uint32_t max, uint32_t default_value);

  // Returns the value negotiated if |negotiated_| is true, otherwise returns
  // default_value_ (used to set default values before negotiation finishes).
  uint32_t GetUint32() const;

  // Serialises |name_| and value to |out|. If |negotiated_| is true then
  // |negotiated_value_| is serialised, otherwise |max_value_| is serialised.
  void ToHandshakeMessage(CryptoHandshakeMessage* out) const override;

  // Sets |negotiated_value_| to the minimum of |max_value_| and the
  // corresponding value from |peer_hello|. If the corresponding value is
  // missing and PRESENCE_OPTIONAL then |negotiated_value_| is set to
  // |default_value_|.
  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details) override;

 private:
  uint32_t max_value_;
  uint32_t default_value_;
  uint32_t negotiated_value_;
};

class NET_EXPORT_PRIVATE QuicNegotiableTag : public QuicNegotiableValue {
 public:
  QuicNegotiableTag(QuicTag name, QuicConfigPresence presence);
  ~QuicNegotiableTag() override;

  // Sets the possible values that |negotiated_tag_| can take after negotiation
  // and the default value that |negotiated_tag_| takes if OPTIONAL and *HLO
  // msg doesn't contain tag |name_|.
  void set(const QuicTagVector& possible_values, QuicTag default_value);

  // Serialises |name_| and vector (either possible or negotiated) to |out|. If
  // |negotiated_| is true then |negotiated_tag_| is serialised, otherwise
  // |possible_values_| is serialised.
  void ToHandshakeMessage(CryptoHandshakeMessage* out) const override;

  // Selects the tag common to both tags in |client_hello| for |name_| and
  // |possible_values_| with preference to tag in |possible_values_|. The
  // selected tag is set as |negotiated_tag_|.
  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details) override;

 private:
  // Reads the vector corresponding to |name_| from |msg| into |out|. If the
  // |name_| is absent in |msg| and |presence_| is set to OPTIONAL |out| is set
  // to |possible_values_|.
  QuicErrorCode ReadVector(const CryptoHandshakeMessage& msg,
                           const QuicTag** out,
                           size_t* out_length,
                           std::string* error_details) const;

  QuicTag negotiated_tag_;
  QuicTagVector possible_values_;
  QuicTag default_value_;
};

// Stores uint32_t from CHLO or SHLO messages that are not negotiated.
class NET_EXPORT_PRIVATE QuicFixedUint32 : public QuicConfigValue {
 public:
  QuicFixedUint32(QuicTag name, QuicConfigPresence presence);
  ~QuicFixedUint32() override;

  bool HasSendValue() const;

  uint32_t GetSendValue() const;

  void SetSendValue(uint32_t value);

  bool HasReceivedValue() const;

  uint32_t GetReceivedValue() const;

  void SetReceivedValue(uint32_t value);

  // If has_send_value is true, serialises |tag_| and |send_value_| to |out|.
  void ToHandshakeMessage(CryptoHandshakeMessage* out) const override;

  // Sets |value_| to the corresponding value from |peer_hello_| if it exists.
  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details) override;

 private:
  uint32_t send_value_;
  bool has_send_value_;
  uint32_t receive_value_;
  bool has_receive_value_;
};

// Stores tag from CHLO or SHLO messages that are not negotiated.
class NET_EXPORT_PRIVATE QuicFixedTagVector : public QuicConfigValue {
 public:
  QuicFixedTagVector(QuicTag name, QuicConfigPresence presence);
  QuicFixedTagVector(const QuicFixedTagVector& other);
  ~QuicFixedTagVector() override;

  bool HasSendValues() const;

  QuicTagVector GetSendValues() const;

  void SetSendValues(const QuicTagVector& values);

  bool HasReceivedValues() const;

  QuicTagVector GetReceivedValues() const;

  void SetReceivedValues(const QuicTagVector& values);

  // If has_send_value is true, serialises |tag_vector_| and |send_value_| to
  // |out|.
  void ToHandshakeMessage(CryptoHandshakeMessage* out) const override;

  // Sets |receive_values_| to the corresponding value from |client_hello_| if
  // it exists.
  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details) override;

 private:
  QuicTagVector send_values_;
  bool has_send_values_;
  QuicTagVector receive_values_;
  bool has_receive_values_;
};

// Stores IPEndPoint from CHLO or SHLO messages that are not negotiated.
class QuicFixedIPEndPoint : public QuicConfigValue {
 public:
  QuicFixedIPEndPoint(QuicTag tag, QuicConfigPresence presence);
  ~QuicFixedIPEndPoint() override;

  bool HasSendValue() const;

  const IPEndPoint& GetSendValue() const;

  void SetSendValue(const IPEndPoint& value);

  bool HasReceivedValue() const;

  const IPEndPoint& GetReceivedValue() const;

  void SetReceivedValue(const IPEndPoint& value);

  void ToHandshakeMessage(CryptoHandshakeMessage* out) const override;

  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details) override;

 private:
  IPEndPoint send_value_;
  bool has_send_value_;
  IPEndPoint receive_value_;
  bool has_receive_value_;
};

// QuicConfig contains non-crypto configuration options that are negotiated in
// the crypto handshake.
class NET_EXPORT_PRIVATE QuicConfig {
 public:
  QuicConfig();
  QuicConfig(const QuicConfig& other);
  ~QuicConfig();

  void SetConnectionOptionsToSend(const QuicTagVector& connection_options);

  bool HasReceivedConnectionOptions() const;

  // Sets initial received connection options.  All received connection options
  // will be initialized with these fields. Initial received options may only be
  // set once per config, prior to the setting of any other options.  If options
  // have already been set (either by previous calls or via handshake), this
  // function does nothing and returns false.
  bool SetInitialReceivedConnectionOptions(const QuicTagVector& tags);

  QuicTagVector ReceivedConnectionOptions() const;

  bool HasSendConnectionOptions() const;

  QuicTagVector SendConnectionOptions() const;

  // Returns true if the client is sending or the server has received a
  // connection option.
  bool HasClientSentConnectionOption(QuicTag tag,
                                     Perspective perspective) const;

  void SetIdleConnectionStateLifetime(
      QuicTime::Delta max_idle_connection_state_lifetime,
      QuicTime::Delta default_idle_conection_state_lifetime);

  QuicTime::Delta IdleConnectionStateLifetime() const;

  void SetSilentClose(bool silent_close);

  bool SilentClose() const;

  void SetMaxStreamsPerConnection(size_t max_streams, size_t default_streams);

  uint32_t MaxStreamsPerConnection() const;

  void SetMaxIncomingDynamicStreamsToSend(
      uint32_t max_incoming_dynamic_streams);

  uint32_t GetMaxIncomingDynamicStreamsToSend();

  bool HasReceivedMaxIncomingDynamicStreams();

  uint32_t ReceivedMaxIncomingDynamicStreams();

  void set_max_time_before_crypto_handshake(
      QuicTime::Delta max_time_before_crypto_handshake) {
    max_time_before_crypto_handshake_ = max_time_before_crypto_handshake;
  }

  QuicTime::Delta max_time_before_crypto_handshake() const {
    return max_time_before_crypto_handshake_;
  }

  void set_max_idle_time_before_crypto_handshake(
      QuicTime::Delta max_idle_time_before_crypto_handshake) {
    max_idle_time_before_crypto_handshake_ =
        max_idle_time_before_crypto_handshake;
  }

  QuicTime::Delta max_idle_time_before_crypto_handshake() const {
    return max_idle_time_before_crypto_handshake_;
  }

  void set_max_undecryptable_packets(size_t max_undecryptable_packets) {
    max_undecryptable_packets_ = max_undecryptable_packets;
  }

  size_t max_undecryptable_packets() const {
    return max_undecryptable_packets_;
  }

  bool HasSetBytesForConnectionIdToSend() const;

  // Sets the peer's connection id length, in bytes.
  void SetBytesForConnectionIdToSend(uint32_t bytes);

  bool HasReceivedBytesForConnectionId() const;

  uint32_t ReceivedBytesForConnectionId() const;

  // Sets an estimated initial round trip time in us.
  void SetInitialRoundTripTimeUsToSend(uint32_t rtt_us);

  bool HasReceivedInitialRoundTripTimeUs() const;

  uint32_t ReceivedInitialRoundTripTimeUs() const;

  bool HasInitialRoundTripTimeUsToSend() const;

  uint32_t GetInitialRoundTripTimeUsToSend() const;

  // Sets an initial stream flow control window size to transmit to the peer.
  void SetInitialStreamFlowControlWindowToSend(uint32_t window_bytes);

  uint32_t GetInitialStreamFlowControlWindowToSend() const;

  bool HasReceivedInitialStreamFlowControlWindowBytes() const;

  uint32_t ReceivedInitialStreamFlowControlWindowBytes() const;

  // Sets an initial session flow control window size to transmit to the peer.
  void SetInitialSessionFlowControlWindowToSend(uint32_t window_bytes);

  uint32_t GetInitialSessionFlowControlWindowToSend() const;

  bool HasReceivedInitialSessionFlowControlWindowBytes() const;

  uint32_t ReceivedInitialSessionFlowControlWindowBytes() const;

  // Sets socket receive buffer to transmit to the peer.
  void SetSocketReceiveBufferToSend(uint32_t window_bytes);

  bool HasReceivedSocketReceiveBuffer() const;

  uint32_t ReceivedSocketReceiveBuffer() const;

  void SetMultipathEnabled(bool multipath_enabled);

  bool MultipathEnabled() const;

  void SetDisableConnectionMigration();

  bool DisableConnectionMigration() const;

  void SetAlternateServerAddressToSend(
      const IPEndPoint& alternate_server_address);

  bool HasReceivedAlternateServerAddress() const;

  const IPEndPoint& ReceivedAlternateServerAddress() const;

  bool negotiated() const;

  // ToHandshakeMessage serialises the settings in this object as a series of
  // tags /value pairs and adds them to |out|.
  void ToHandshakeMessage(CryptoHandshakeMessage* out) const;

  // Calls ProcessPeerHello on each negotiable parameter. On failure returns
  // the corresponding QuicErrorCode and sets detailed error in |error_details|.
  QuicErrorCode ProcessPeerHello(const CryptoHandshakeMessage& peer_hello,
                                 HelloType hello_type,
                                 std::string* error_details);

 private:
  friend class test::QuicConfigPeer;

  // SetDefaults sets the members to sensible, default values.
  void SetDefaults();

  // Configurations options that are not negotiated.
  // Maximum time the session can be alive before crypto handshake is finished.
  QuicTime::Delta max_time_before_crypto_handshake_;
  // Maximum idle time before the crypto handshake has completed.
  QuicTime::Delta max_idle_time_before_crypto_handshake_;
  // Maximum number of undecryptable packets stored before CHLO/SHLO.
  size_t max_undecryptable_packets_;

  // Connection options.
  QuicFixedTagVector connection_options_;
  // Idle connection state lifetime
  QuicNegotiableUint32 idle_connection_state_lifetime_seconds_;
  // Whether to use silent close.  Defaults to 0 (false) and is otherwise true.
  QuicNegotiableUint32 silent_close_;
  // Maximum number of streams that the connection can support.
  // TODO(rjshade): Remove when removing QUIC_VERSION_34
  QuicNegotiableUint32 max_streams_per_connection_;
  // Maximum number of incoming dynamic streams that the connection can support.
  QuicFixedUint32 max_incoming_dynamic_streams_;
  // The number of bytes required for the connection ID.
  QuicFixedUint32 bytes_for_connection_id_;
  // Initial round trip time estimate in microseconds.
  QuicFixedUint32 initial_round_trip_time_us_;

  // Initial stream flow control receive window in bytes.
  QuicFixedUint32 initial_stream_flow_control_window_bytes_;
  // Initial session flow control receive window in bytes.
  QuicFixedUint32 initial_session_flow_control_window_bytes_;

  // Socket receive buffer in bytes.
  // TODO(ianswett): Deprecate once QUIC_VERSION_34 is deprecated.
  QuicFixedUint32 socket_receive_buffer_;

  // Whether to support multipath for this connection.
  QuicNegotiableUint32 multipath_enabled_;

  // Whether tell peer not to attempt connection migration.
  QuicFixedUint32 connection_migration_disabled_;

  // An alternate server address the client could connect to.
  QuicFixedIPEndPoint alternate_server_address_;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_CONFIG_H_
