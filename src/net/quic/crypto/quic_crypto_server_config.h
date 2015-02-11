// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_QUIC_CRYPTO_SERVER_CONFIG_H_
#define NET_QUIC_CRYPTO_QUIC_CRYPTO_SERVER_CONFIG_H_

#include <map>
#include <string>
#include <vector>

#include "base/memory/ref_counted.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/cached_network_parameters.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/crypto_secret_boxer.h"
#include "net/quic/crypto/source_address_token.h"
#include "net/quic/quic_time.h"

namespace net {

class CryptoHandshakeMessage;
class EphemeralKeySource;
class KeyExchange;
class ProofSource;
class QuicClock;
class QuicDecrypter;
class QuicEncrypter;
class QuicRandom;
class QuicServerConfigProtobuf;
class StrikeRegister;
class StrikeRegisterClient;

// ClientHelloInfo contains information about a client hello message that is
// only kept for as long as it's being processed.
struct ClientHelloInfo {
  ClientHelloInfo(const IPEndPoint& in_client_ip, QuicWallTime in_now);
  ~ClientHelloInfo();

  // Inputs to EvaluateClientHello.
  const IPEndPoint client_ip;
  const QuicWallTime now;

  // Outputs from EvaluateClientHello.
  bool valid_source_address_token;
  bool client_nonce_well_formed;
  bool unique;
  base::StringPiece sni;
  base::StringPiece client_nonce;
  base::StringPiece server_nonce;
  base::StringPiece user_agent_id;
  SourceAddressTokens source_address_tokens;

  // Errors from EvaluateClientHello.
  std::vector<uint32> reject_reasons;
  static_assert(sizeof(QuicTag) == sizeof(uint32), "header out of sync");
};

namespace test {
class QuicCryptoServerConfigPeer;
}  // namespace test

// Hook that allows application code to subscribe to primary config changes.
class PrimaryConfigChangedCallback {
 public:
  PrimaryConfigChangedCallback();
  virtual ~PrimaryConfigChangedCallback();
  virtual void Run(const std::string& scid) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(PrimaryConfigChangedCallback);
};

// Callback used to accept the result of the |client_hello| validation step.
class NET_EXPORT_PRIVATE ValidateClientHelloResultCallback {
 public:
  // Opaque token that holds information about the client_hello and
  // its validity.  Can be interpreted by calling ProcessClientHello.
  struct Result {
    Result(const CryptoHandshakeMessage& in_client_hello,
           IPEndPoint in_client_ip,
           QuicWallTime in_now);
    ~Result();

    CryptoHandshakeMessage client_hello;
    ClientHelloInfo info;
    QuicErrorCode error_code;
    std::string error_details;

    // Populated if the CHLO STK contained a CachedNetworkParameters proto.
    CachedNetworkParameters cached_network_params;
  };

  ValidateClientHelloResultCallback();
  virtual ~ValidateClientHelloResultCallback();
  void Run(const Result* result);

 protected:
  virtual void RunImpl(const CryptoHandshakeMessage& client_hello,
                       const Result& result) = 0;

 private:
  DISALLOW_COPY_AND_ASSIGN(ValidateClientHelloResultCallback);
};

// QuicCryptoServerConfig contains the crypto configuration of a QUIC server.
// Unlike a client, a QUIC server can have multiple configurations active in
// order to support clients resuming with a previous configuration.
// TODO(agl): when adding configurations at runtime is added, this object will
// need to consider locking.
class NET_EXPORT_PRIVATE QuicCryptoServerConfig {
 public:
  // ConfigOptions contains options for generating server configs.
  struct NET_EXPORT_PRIVATE ConfigOptions {
    ConfigOptions();

    // expiry_time is the time, in UNIX seconds, when the server config will
    // expire. If unset, it defaults to the current time plus six months.
    QuicWallTime expiry_time;
    // channel_id_enabled controls whether the server config will indicate
    // support for ChannelIDs.
    bool channel_id_enabled;
    // id contains the server config id for the resulting config. If empty, a
    // random id is generated.
    std::string id;
    // orbit contains the kOrbitSize bytes of the orbit value for the server
    // config. If |orbit| is empty then a random orbit is generated.
    std::string orbit;
    // p256 determines whether a P-256 public key will be included in the
    // server config. Note that this breaks deterministic server-config
    // generation since P-256 key generation doesn't use the QuicRandom given
    // to DefaultConfig().
    bool p256;
  };

  // |source_address_token_secret|: secret key material used for encrypting and
  //     decrypting source address tokens. It can be of any length as it is fed
  //     into a KDF before use. In tests, use TESTING.
  // |server_nonce_entropy|: an entropy source used to generate the orbit and
  //     key for server nonces, which are always local to a given instance of a
  //     server.
  QuicCryptoServerConfig(base::StringPiece source_address_token_secret,
                         QuicRandom* server_nonce_entropy);
  ~QuicCryptoServerConfig();

  // TESTING is a magic parameter for passing to the constructor in tests.
  static const char TESTING[];

  // Generates a QuicServerConfigProtobuf protobuf suitable for
  // AddConfig and SetConfigs.
  static QuicServerConfigProtobuf* GenerateConfig(
      QuicRandom* rand,
      const QuicClock* clock,
      const ConfigOptions& options);

  // AddConfig adds a QuicServerConfigProtobuf to the availible configurations.
  // It returns the SCFG message from the config if successful. The caller
  // takes ownership of the CryptoHandshakeMessage. |now| is used in
  // conjunction with |protobuf->primary_time()| to determine whether the
  // config should be made primary.
  CryptoHandshakeMessage* AddConfig(QuicServerConfigProtobuf* protobuf,
                                    QuicWallTime now);

  // AddDefaultConfig calls DefaultConfig to create a config and then calls
  // AddConfig to add it. See the comment for |DefaultConfig| for details of
  // the arguments.
  CryptoHandshakeMessage* AddDefaultConfig(
      QuicRandom* rand,
      const QuicClock* clock,
      const ConfigOptions& options);

  // SetConfigs takes a vector of config protobufs and the current time.
  // Configs are assumed to be uniquely identified by their server config ID.
  // Previously unknown configs are added and possibly made the primary config
  // depending on their |primary_time| and the value of |now|. Configs that are
  // known, but are missing from the protobufs are deleted, unless they are
  // currently the primary config. SetConfigs returns false if any errors were
  // encountered and no changes to the QuicCryptoServerConfig will occur.
  bool SetConfigs(const std::vector<QuicServerConfigProtobuf*>& protobufs,
                  QuicWallTime now);

  // Get the server config ids for all known configs.
  void GetConfigIds(std::vector<std::string>* scids) const;

  // Checks |client_hello| for gross errors and determines whether it
  // can be shown to be fresh (i.e. not a replay).  The result of the
  // validation step must be interpreted by calling
  // QuicCryptoServerConfig::ProcessClientHello from the done_cb.
  //
  // ValidateClientHello may invoke the done_cb before unrolling the
  // stack if it is able to assess the validity of the client_nonce
  // without asynchronous operations.
  //
  // client_hello: the incoming client hello message.
  // client_ip: the IP address of the client, which is used to generate and
  //     validate source-address tokens.
  // clock: used to validate client nonces and ephemeral keys.
  // done_cb: single-use callback that accepts an opaque
  //     ValidatedClientHelloMsg token that holds information about
  //     the client hello.  The callback will always be called exactly
  //     once, either under the current call stack, or after the
  //     completion of an asynchronous operation.
  void ValidateClientHello(
      const CryptoHandshakeMessage& client_hello,
      IPEndPoint client_ip,
      const QuicClock* clock,
      ValidateClientHelloResultCallback* done_cb) const;

  // ProcessClientHello processes |client_hello| and decides whether to accept
  // or reject the connection. If the connection is to be accepted, |out| is
  // set to the contents of the ServerHello, |out_params| is completed and
  // QUIC_NO_ERROR is returned. Otherwise |out| is set to be a REJ message and
  // an error code is returned.
  //
  // validate_chlo_result: Output from the asynchronous call to
  //     ValidateClientHello.  Contains the client hello message and
  //     information about it.
  // connection_id: the ConnectionId for the connection, which is used in key
  //     derivation.
  // server_ip: the IP address and port of the server. The IP address may be
  //     used for certificate selection.
  // client_address: the IP address and port of the client. The IP address is
  //     used to generate and validate source-address tokens.
  // version: version of the QUIC protocol in use for this connection
  // supported_versions: versions of the QUIC protocol that this server
  //     supports.
  // initial_flow_control_window: size of initial flow control window this
  //     server uses for new streams.
  // clock: used to validate client nonces and ephemeral keys.
  // rand: an entropy source
  // params: the state of the handshake. This may be updated with a server
  //     nonce when we send a rejection. After a successful handshake, this will
  //     contain the state of the connection.
  // out: the resulting handshake message (either REJ or SHLO)
  // error_details: used to store a string describing any error.
  QuicErrorCode ProcessClientHello(
      const ValidateClientHelloResultCallback::Result& validate_chlo_result,
      QuicConnectionId connection_id,
      const IPEndPoint& server_ip,
      const IPEndPoint& client_address,
      QuicVersion version,
      const QuicVersionVector& supported_versions,
      const QuicClock* clock,
      QuicRandom* rand,
      QuicCryptoNegotiatedParameters* params,
      CryptoHandshakeMessage* out,
      std::string* error_details) const;

  // BuildServerConfigUpdateMessage sets |out| to be a SCUP message containing
  // the current primary config, an up to date source-address token, and cert
  // chain and proof in the case of secure QUIC. Returns true if successfully
  // filled |out|.
  //
  // |cached_network_params| is optional, and can be nullptr.
  bool BuildServerConfigUpdateMessage(
      const SourceAddressTokens& previous_source_address_tokens,
      const IPEndPoint& server_ip,
      const IPEndPoint& client_ip,
      const QuicClock* clock,
      QuicRandom* rand,
      const QuicCryptoNegotiatedParameters& params,
      const CachedNetworkParameters* cached_network_params,
      CryptoHandshakeMessage* out) const;

  // SetProofSource installs |proof_source| as the ProofSource for handshakes.
  // This object takes ownership of |proof_source|.
  void SetProofSource(ProofSource* proof_source);

  // SetEphemeralKeySource installs an object that can cache ephemeral keys for
  // a short period of time. This object takes ownership of
  // |ephemeral_key_source|. If not set then ephemeral keys will be generated
  // per-connection.
  void SetEphemeralKeySource(EphemeralKeySource* ephemeral_key_source);

  // Install an externall created StrikeRegisterClient for use to
  // interact with the strike register.  This object takes ownership
  // of the |strike_register_client|.
  void SetStrikeRegisterClient(StrikeRegisterClient* strike_register_client);

  // set_replay_protection controls whether replay protection is enabled. If
  // replay protection is disabled then no strike registers are needed and
  // frontends can share an orbit value without a shared strike-register.
  // However, an attacker can duplicate a handshake and cause a client's
  // request to be processed twice.
  void set_replay_protection(bool on);

  // set_strike_register_no_startup_period configures the strike register to
  // not have a startup period.
  void set_strike_register_no_startup_period();

  // set_strike_register_max_entries sets the maximum number of entries that
  // the internal strike register will hold. If the strike register fills up
  // then the oldest entries (by the client's clock) will be dropped.
  void set_strike_register_max_entries(uint32 max_entries);

  // set_strike_register_window_secs sets the number of seconds around the
  // current time that the strike register will attempt to be authoritative
  // for. Setting a larger value allows for greater client clock-skew, but
  // means that the quiescent startup period must be longer.
  void set_strike_register_window_secs(uint32 window_secs);

  // set_source_address_token_future_secs sets the number of seconds into the
  // future that source-address tokens will be accepted from. Since
  // source-address tokens are authenticated, this should only happen if
  // another, valid server has clock-skew.
  void set_source_address_token_future_secs(uint32 future_secs);

  // set_source_address_token_lifetime_secs sets the number of seconds that a
  // source-address token will be valid for.
  void set_source_address_token_lifetime_secs(uint32 lifetime_secs);

  // set_server_nonce_strike_register_max_entries sets the number of entries in
  // the server-nonce strike-register. This is used to record that server nonce
  // values have been used. If the number of entries is too small then clients
  // which are depending on server nonces may fail to handshake because their
  // nonce has expired in the amount of time it took to go from the server to
  // the client and back.
  void set_server_nonce_strike_register_max_entries(uint32 max_entries);

  // set_server_nonce_strike_register_window_secs sets the number of seconds
  // around the current time that the server-nonce strike-register will accept
  // nonces from. Setting a larger value allows for clients to delay follow-up
  // client hellos for longer and still use server nonces as proofs of
  // uniqueness.
  void set_server_nonce_strike_register_window_secs(uint32 window_secs);

  // Set and take ownership of the callback to invoke on primary config changes.
  void AcquirePrimaryConfigChangedCb(PrimaryConfigChangedCallback* cb);

  // Returns true if this config has a |proof_source_|.
  bool HasProofSource() const;

 private:
  friend class test::QuicCryptoServerConfigPeer;

  // Config represents a server config: a collection of preferences and
  // Diffie-Hellman public values.
  class NET_EXPORT_PRIVATE Config : public QuicCryptoConfig,
                                    public base::RefCounted<Config> {
   public:
    Config();

    // TODO(rtenneti): since this is a class, we should probably do
    // getters/setters here.
    // |serialized| contains the bytes of this server config, suitable for
    // sending on the wire.
    std::string serialized;
    // id contains the SCID of this server config.
    std::string id;
    // orbit contains the orbit value for this config: an opaque identifier
    // used to identify clusters of server frontends.
    unsigned char orbit[kOrbitSize];

    // key_exchanges contains key exchange objects with the private keys
    // already loaded. The values correspond, one-to-one, with the tags in
    // |kexs| from the parent class.
    std::vector<KeyExchange*> key_exchanges;

    // tag_value_map contains the raw key/value pairs for the config.
    QuicTagValueMap tag_value_map;

    // channel_id_enabled is true if the config in |serialized| specifies that
    // ChannelIDs are supported.
    bool channel_id_enabled;

    // is_primary is true if this config is the one that we'll give out to
    // clients as the current one.
    bool is_primary;

    // primary_time contains the timestamp when this config should become the
    // primary config. A value of QuicWallTime::Zero() means that this config
    // will not be promoted at a specific time.
    QuicWallTime primary_time;

    // Secondary sort key for use when selecting primary configs and
    // there are multiple configs with the same primary time.
    // Smaller numbers mean higher priority.
    uint64 priority;

    // source_address_token_boxer_ is used to protect the
    // source-address tokens that are given to clients.
    // Points to either source_address_token_boxer_storage or the
    // default boxer provided by QuicCryptoServerConfig.
    const CryptoSecretBoxer* source_address_token_boxer;

    // Holds the override source_address_token_boxer instance if the
    // Config is not using the default source address token boxer
    // instance provided by QuicCryptoServerConfig.
    scoped_ptr<CryptoSecretBoxer> source_address_token_boxer_storage;

   private:
    friend class base::RefCounted<Config>;

    virtual ~Config();

    DISALLOW_COPY_AND_ASSIGN(Config);
  };

  typedef std::map<ServerConfigID, scoped_refptr<Config> > ConfigMap;

  // Get a ref to the config with a given server config id.
  scoped_refptr<Config> GetConfigWithScid(
      base::StringPiece requested_scid) const;

  // ConfigPrimaryTimeLessThan returns true if a->primary_time <
  // b->primary_time.
  static bool ConfigPrimaryTimeLessThan(const scoped_refptr<Config>& a,
                                        const scoped_refptr<Config>& b);

  // SelectNewPrimaryConfig reevaluates the primary config based on the
  // "primary_time" deadlines contained in each.
  void SelectNewPrimaryConfig(QuicWallTime now) const;

  // EvaluateClientHello checks |client_hello| for gross errors and determines
  // whether it can be shown to be fresh (i.e. not a replay). The results are
  // written to |info|.
  void EvaluateClientHello(
      const uint8* primary_orbit,
      scoped_refptr<Config> requested_config,
      ValidateClientHelloResultCallback::Result* client_hello_state,
      ValidateClientHelloResultCallback* done_cb) const;

  // BuildRejection sets |out| to be a REJ message in reply to |client_hello|.
  void BuildRejection(const IPEndPoint& server_ip,
                      const Config& config,
                      const CryptoHandshakeMessage& client_hello,
                      const ClientHelloInfo& info,
                      const CachedNetworkParameters& cached_network_params,
                      QuicRandom* rand,
                      QuicCryptoNegotiatedParameters* params,
                      CryptoHandshakeMessage* out) const;

  // ParseConfigProtobuf parses the given config protobuf and returns a
  // scoped_refptr<Config> if successful. The caller adopts the reference to the
  // Config. On error, ParseConfigProtobuf returns nullptr.
  scoped_refptr<Config> ParseConfigProtobuf(QuicServerConfigProtobuf* protobuf);

  // NewSourceAddressToken returns a fresh source address token for the given
  // IP address. |cached_network_params| is optional, and can be nullptr.
  std::string NewSourceAddressToken(
      const Config& config,
      const SourceAddressTokens& previous_tokens,
      const IPEndPoint& ip,
      QuicRandom* rand,
      QuicWallTime now,
      const CachedNetworkParameters* cached_network_params) const;

  // ParseSourceAddressToken parses the source address tokens contained in
  // the encrypted |token|, and populates |tokens| with the parsed tokens.
  // Returns HANDSHAKE_OK if |token| could be parsed, or the reason for the
  // failure.
  HandshakeFailureReason ParseSourceAddressToken(
      const Config& config,
      base::StringPiece token,
      SourceAddressTokens* tokens) const;

  // ValidateSourceAddressToken returns HANDSHAKE_OK if the source address
  // tokens in |tokens| contain a valid and timely token for the IP address
  // |ip| given that the current time is |now|. Otherwise it returns the
  // reason for failure. |cached_network_params| is populated if the valid
  // token contains a CachedNetworkParameters proto.
  // TODO(rch): remove this method when we remove:
  // FLAGS_quic_use_multiple_address_in_source_tokens.
  HandshakeFailureReason ValidateSourceAddressToken(
      const Config& config,
      base::StringPiece token,
      const IPEndPoint& ip,
      QuicWallTime now,
      CachedNetworkParameters* cached_network_params) const;

  // ValidateSourceAddressTokens returns HANDSHAKE_OK if the source address
  // tokens in |tokens| contain a valid and timely token for the IP address
  // |ip| given that the current time is |now|. Otherwise it returns the
  // reason for failure. |cached_network_params| is populated if the valid
  // token contains a CachedNetworkParameters proto.
  HandshakeFailureReason ValidateSourceAddressTokens(
      const SourceAddressTokens& tokens,
      const IPEndPoint& ip,
      QuicWallTime now,
      CachedNetworkParameters* cached_network_params) const;

  // ValidateSingleSourceAddressToken returns HANDSHAKE_OK if the source
  // address token in |token| is a timely token for the IP address |ip|
  // given that the current time is |now|. Otherwise it returns the reason
  // for failure.
  HandshakeFailureReason ValidateSingleSourceAddressToken(
      const SourceAddressToken& token,
      const IPEndPoint& ip,
      QuicWallTime now) const;

  // Returns HANDSHAKE_OK if the source address token in |token| is a timely
  // token given that the current time is |now|. Otherwise it returns the
  // reason for failure.
  HandshakeFailureReason ValidateSourceAddressTokenTimestamp(
      const SourceAddressToken& token,
      QuicWallTime now) const;

  // NewServerNonce generates and encrypts a random nonce.
  std::string NewServerNonce(QuicRandom* rand, QuicWallTime now) const;

  // ValidateServerNonce decrypts |token| and verifies that it hasn't been
  // previously used and is recent enough that it is plausible that it was part
  // of a very recently provided rejection ("recent" will be on the order of
  // 10-30 seconds). If so, it records that it has been used and returns
  // HANDSHAKE_OK. Otherwise it returns the reason for failure.
  HandshakeFailureReason ValidateServerNonce(
      base::StringPiece echoed_server_nonce,
      QuicWallTime now) const;

  // replay_protection_ controls whether the server enforces that handshakes
  // aren't replays.
  bool replay_protection_;

  // configs_ satisfies the following invariants:
  //   1) configs_.empty() <-> primary_config_ == nullptr
  //   2) primary_config_ != nullptr -> primary_config_->is_primary
  //   3) ∀ c∈configs_, c->is_primary <-> c == primary_config_
  mutable base::Lock configs_lock_;
  // configs_ contains all active server configs. It's expected that there are
  // about half-a-dozen configs active at any one time.
  ConfigMap configs_;
  // primary_config_ points to a Config (which is also in |configs_|) which is
  // the primary config - i.e. the one that we'll give out to new clients.
  mutable scoped_refptr<Config> primary_config_;
  // next_config_promotion_time_ contains the nearest, future time when an
  // active config will be promoted to primary.
  mutable QuicWallTime next_config_promotion_time_;
  // Callback to invoke when the primary config changes.
  scoped_ptr<PrimaryConfigChangedCallback> primary_config_changed_cb_;

  // Protects access to the pointer held by strike_register_client_.
  mutable base::Lock strike_register_client_lock_;
  // strike_register_ contains a data structure that keeps track of previously
  // observed client nonces in order to prevent replay attacks.
  mutable scoped_ptr<StrikeRegisterClient> strike_register_client_;

  // Default source_address_token_boxer_ used to protect the
  // source-address tokens that are given to clients.  Individual
  // configs may use boxers with alternate secrets.
  CryptoSecretBoxer default_source_address_token_boxer_;

  // server_nonce_boxer_ is used to encrypt and validate suggested server
  // nonces.
  CryptoSecretBoxer server_nonce_boxer_;

  // server_nonce_orbit_ contains the random, per-server orbit values that this
  // server will use to generate server nonces (the moral equivalent of a SYN
  // cookies).
  uint8 server_nonce_orbit_[8];

  mutable base::Lock server_nonce_strike_register_lock_;
  // server_nonce_strike_register_ contains a data structure that keeps track of
  // previously observed server nonces from this server, in order to prevent
  // replay attacks.
  mutable scoped_ptr<StrikeRegister> server_nonce_strike_register_;

  // proof_source_ contains an object that can provide certificate chains and
  // signatures.
  scoped_ptr<ProofSource> proof_source_;

  // ephemeral_key_source_ contains an object that caches ephemeral keys for a
  // short period of time.
  scoped_ptr<EphemeralKeySource> ephemeral_key_source_;

  // These fields store configuration values. See the comments for their
  // respective setter functions.
  bool strike_register_no_startup_period_;
  uint32 strike_register_max_entries_;
  uint32 strike_register_window_secs_;
  uint32 source_address_token_future_secs_;
  uint32 source_address_token_lifetime_secs_;
  uint32 server_nonce_strike_register_max_entries_;
  uint32 server_nonce_strike_register_window_secs_;

  DISALLOW_COPY_AND_ASSIGN(QuicCryptoServerConfig);
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_QUIC_CRYPTO_SERVER_CONFIG_H_
