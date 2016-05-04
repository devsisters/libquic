// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/quic_crypto_server_config.h"

#include <stdlib.h>

#include <algorithm>
#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/hkdf.h"
#include "crypto/secure_hash.h"
#include "net/base/ip_address.h"
#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"
#include "net/quic/crypto/aes_128_gcm_12_encrypter.h"
#include "net/quic/crypto/cert_compressor.h"
#include "net/quic/crypto/chacha20_poly1305_encrypter.h"
#include "net/quic/crypto/channel_id.h"
#include "net/quic/crypto/crypto_framer.h"
#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/crypto/crypto_server_config_protobuf.h"
#include "net/quic/crypto/crypto_utils.h"
#include "net/quic/crypto/curve25519_key_exchange.h"
#include "net/quic/crypto/ephemeral_key_source.h"
#include "net/quic/crypto/key_exchange.h"
#include "net/quic/crypto/local_strike_register_client.h"
#include "net/quic/crypto/p256_key_exchange.h"
#include "net/quic/crypto/proof_source.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/crypto/strike_register.h"
#include "net/quic/crypto/strike_register_client.h"
#include "net/quic/proto/source_address_token.pb.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_socket_address_coder.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using crypto::SecureHash;
using std::map;
using std::sort;
using std::string;
using std::vector;

namespace net {

namespace {

// kMultiplier is the multiple of the CHLO message size that a REJ message
// must stay under when the client doesn't present a valid source-address
// token. This is used to protect QUIC from amplification attacks.
// TODO(rch): Reduce this to 2 again once b/25933682 is fixed.
const size_t kMultiplier = 3;

const int kMaxTokenAddresses = 4;

string DeriveSourceAddressTokenKey(StringPiece source_address_token_secret) {
  crypto::HKDF hkdf(source_address_token_secret, StringPiece() /* no salt */,
                    "QUIC source address token key",
                    CryptoSecretBoxer::GetKeySize(), 0 /* no fixed IV needed */,
                    0 /* no subkey secret */);
  return hkdf.server_write_key().as_string();
}

IPAddress DualstackIPAddress(const IPAddress& ip) {
  if (ip.IsIPv4()) {
    return ConvertIPv4ToIPv4MappedIPv6(ip);
  }
  return ip;
}

}  // namespace

class ValidateClientHelloHelper {
 public:
  ValidateClientHelloHelper(ValidateClientHelloResultCallback::Result* result,
                            ValidateClientHelloResultCallback* done_cb)
      : result_(result), done_cb_(done_cb) {}

  ~ValidateClientHelloHelper() {
    QUIC_BUG_IF(done_cb_ != nullptr)
        << "Deleting ValidateClientHelloHelper with a pending callback.";
  }

  void ValidationComplete(QuicErrorCode error_code, const char* error_details) {
    result_->error_code = error_code;
    result_->error_details = error_details;
    done_cb_->Run(result_);
    DetachCallback();
  }

  void StartedAsyncCallback() { DetachCallback(); }

 private:
  void DetachCallback() {
    QUIC_BUG_IF(done_cb_ == nullptr) << "Callback already detached.";
    done_cb_ = nullptr;
  }

  ValidateClientHelloResultCallback::Result* result_;
  ValidateClientHelloResultCallback* done_cb_;

  DISALLOW_COPY_AND_ASSIGN(ValidateClientHelloHelper);
};

class VerifyNonceIsValidAndUniqueCallback
    : public StrikeRegisterClient::ResultCallback {
 public:
  VerifyNonceIsValidAndUniqueCallback(
      ValidateClientHelloResultCallback::Result* result,
      ValidateClientHelloResultCallback* done_cb)
      : result_(result), done_cb_(done_cb) {}

 protected:
  void RunImpl(bool nonce_is_valid_and_unique,
               InsertStatus nonce_error) override {
    DVLOG(1) << "Using client nonce, unique: " << nonce_is_valid_and_unique
             << " nonce_error: " << nonce_error;
    if (!nonce_is_valid_and_unique) {
      HandshakeFailureReason client_nonce_error;
      switch (nonce_error) {
        case NONCE_INVALID_FAILURE:
          client_nonce_error = CLIENT_NONCE_INVALID_FAILURE;
          break;
        case NONCE_NOT_UNIQUE_FAILURE:
          client_nonce_error = CLIENT_NONCE_NOT_UNIQUE_FAILURE;
          break;
        case NONCE_INVALID_ORBIT_FAILURE:
          client_nonce_error = CLIENT_NONCE_INVALID_ORBIT_FAILURE;
          break;
        case NONCE_INVALID_TIME_FAILURE:
          client_nonce_error = CLIENT_NONCE_INVALID_TIME_FAILURE;
          break;
        case STRIKE_REGISTER_TIMEOUT:
          client_nonce_error = CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT;
          break;
        case STRIKE_REGISTER_FAILURE:
          client_nonce_error = CLIENT_NONCE_STRIKE_REGISTER_FAILURE;
          break;
        case NONCE_UNKNOWN_FAILURE:
          client_nonce_error = CLIENT_NONCE_UNKNOWN_FAILURE;
          break;
        case NONCE_OK:
        default:
          QUIC_BUG << "Unexpected client nonce error: " << nonce_error;
          client_nonce_error = CLIENT_NONCE_UNKNOWN_FAILURE;
          break;
      }
      result_->info.reject_reasons.push_back(client_nonce_error);
    }
    done_cb_->Run(result_);
  }

 private:
  ValidateClientHelloResultCallback::Result* result_;
  ValidateClientHelloResultCallback* done_cb_;

  DISALLOW_COPY_AND_ASSIGN(VerifyNonceIsValidAndUniqueCallback);
};

// static
const char QuicCryptoServerConfig::TESTING[] = "secret string for testing";

ClientHelloInfo::ClientHelloInfo(const IPAddress& in_client_ip,
                                 QuicWallTime in_now)
    : client_ip(in_client_ip), now(in_now), valid_source_address_token(false) {}

ClientHelloInfo::~ClientHelloInfo() {}

PrimaryConfigChangedCallback::PrimaryConfigChangedCallback() {}

PrimaryConfigChangedCallback::~PrimaryConfigChangedCallback() {}

ValidateClientHelloResultCallback::Result::Result(
    const CryptoHandshakeMessage& in_client_hello,
    IPAddress in_client_ip,
    QuicWallTime in_now)
    : client_hello(in_client_hello),
      info(in_client_ip, in_now),
      error_code(QUIC_NO_ERROR) {}

ValidateClientHelloResultCallback::Result::~Result() {}

ValidateClientHelloResultCallback::ValidateClientHelloResultCallback() {}

ValidateClientHelloResultCallback::~ValidateClientHelloResultCallback() {}

void ValidateClientHelloResultCallback::Run(const Result* result) {
  RunImpl(result->client_hello, *result);
  delete result;
  delete this;
}

QuicCryptoServerConfig::ConfigOptions::ConfigOptions()
    : expiry_time(QuicWallTime::Zero()),
      channel_id_enabled(false),
      token_binding_enabled(false),
      p256(false) {}

QuicCryptoServerConfig::ConfigOptions::ConfigOptions(
    const ConfigOptions& other) = default;

QuicCryptoServerConfig::QuicCryptoServerConfig(
    StringPiece source_address_token_secret,
    QuicRandom* server_nonce_entropy,
    ProofSource* proof_source)
    : replay_protection_(true),
      chlo_multiplier_(kMultiplier),
      configs_lock_(),
      primary_config_(nullptr),
      next_config_promotion_time_(QuicWallTime::Zero()),
      server_nonce_strike_register_lock_(),
      proof_source_(proof_source),
      strike_register_no_startup_period_(false),
      strike_register_max_entries_(1 << 10),
      strike_register_window_secs_(600),
      source_address_token_future_secs_(3600),
      source_address_token_lifetime_secs_(86400),
      server_nonce_strike_register_max_entries_(1 << 10),
      server_nonce_strike_register_window_secs_(120),
      enable_serving_sct_(false) {
  DCHECK(proof_source_.get());
  default_source_address_token_boxer_.SetKeys(
      {DeriveSourceAddressTokenKey(source_address_token_secret)});

  // Generate a random key and orbit for server nonces.
  server_nonce_entropy->RandBytes(server_nonce_orbit_,
                                  sizeof(server_nonce_orbit_));
  const size_t key_size = server_nonce_boxer_.GetKeySize();
  std::unique_ptr<uint8_t[]> key_bytes(new uint8_t[key_size]);
  server_nonce_entropy->RandBytes(key_bytes.get(), key_size);

  server_nonce_boxer_.SetKeys(
      {string(reinterpret_cast<char*>(key_bytes.get()), key_size)});
}

QuicCryptoServerConfig::~QuicCryptoServerConfig() {
  primary_config_ = nullptr;
}

// static
QuicServerConfigProtobuf* QuicCryptoServerConfig::GenerateConfig(
    QuicRandom* rand,
    const QuicClock* clock,
    const ConfigOptions& options) {
  CryptoHandshakeMessage msg;

  const string curve25519_private_key =
      Curve25519KeyExchange::NewPrivateKey(rand);
  std::unique_ptr<Curve25519KeyExchange> curve25519(
      Curve25519KeyExchange::New(curve25519_private_key));
  StringPiece curve25519_public_value = curve25519->public_value();

  string encoded_public_values;
  // First three bytes encode the length of the public value.
  DCHECK_LT(curve25519_public_value.size(), (1U << 24));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size()));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 8));
  encoded_public_values.push_back(
      static_cast<char>(curve25519_public_value.size() >> 16));
  encoded_public_values.append(curve25519_public_value.data(),
                               curve25519_public_value.size());

  string p256_private_key;
  if (options.p256) {
    p256_private_key = P256KeyExchange::NewPrivateKey();
    std::unique_ptr<P256KeyExchange> p256(
        P256KeyExchange::New(p256_private_key));
    StringPiece p256_public_value = p256->public_value();

    DCHECK_LT(p256_public_value.size(), (1U << 24));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size()));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 8));
    encoded_public_values.push_back(
        static_cast<char>(p256_public_value.size() >> 16));
    encoded_public_values.append(p256_public_value.data(),
                                 p256_public_value.size());
  }

  msg.set_tag(kSCFG);
  if (options.p256) {
    msg.SetTaglist(kKEXS, kC255, kP256, 0);
  } else {
    msg.SetTaglist(kKEXS, kC255, 0);
  }
  if (FLAGS_quic_crypto_server_config_default_has_chacha20) {
    msg.SetTaglist(kAEAD, kAESG, kCC20, 0);
  } else {
    msg.SetTaglist(kAEAD, kAESG, 0);
  }
  msg.SetStringPiece(kPUBS, encoded_public_values);

  if (options.expiry_time.IsZero()) {
    const QuicWallTime now = clock->WallNow();
    const QuicWallTime expiry = now.Add(QuicTime::Delta::FromSeconds(
        60 * 60 * 24 * 180 /* 180 days, ~six months */));
    const uint64_t expiry_seconds = expiry.ToUNIXSeconds();
    msg.SetValue(kEXPY, expiry_seconds);
  } else {
    msg.SetValue(kEXPY, options.expiry_time.ToUNIXSeconds());
  }

  char orbit_bytes[kOrbitSize];
  if (options.orbit.size() == sizeof(orbit_bytes)) {
    memcpy(orbit_bytes, options.orbit.data(), sizeof(orbit_bytes));
  } else {
    DCHECK(options.orbit.empty());
    rand->RandBytes(orbit_bytes, sizeof(orbit_bytes));
  }
  msg.SetStringPiece(kORBT, StringPiece(orbit_bytes, sizeof(orbit_bytes)));

  if (options.channel_id_enabled) {
    msg.SetTaglist(kPDMD, kCHID, 0);
  }

  if (options.token_binding_enabled) {
    msg.SetTaglist(kTBKP, kP256, 0);
  }

  if (options.id.empty()) {
    // We need to ensure that the SCID changes whenever the server config does
    // thus we make it a hash of the rest of the server config.
    std::unique_ptr<QuicData> serialized(
        CryptoFramer::ConstructHandshakeMessage(msg));
    std::unique_ptr<SecureHash> hash(SecureHash::Create(SecureHash::SHA256));
    hash->Update(serialized->data(), serialized->length());

    char scid_bytes[16];
    hash->Finish(scid_bytes, sizeof(scid_bytes));
    msg.SetStringPiece(kSCID, StringPiece(scid_bytes, sizeof(scid_bytes)));
  } else {
    msg.SetStringPiece(kSCID, options.id);
  }
  // Don't put new tags below this point. The SCID generation should hash over
  // everything but itself and so extra tags should be added prior to the
  // preceeding if block.

  std::unique_ptr<QuicData> serialized(
      CryptoFramer::ConstructHandshakeMessage(msg));

  std::unique_ptr<QuicServerConfigProtobuf> config(
      new QuicServerConfigProtobuf);
  config->set_config(serialized->AsStringPiece());
  QuicServerConfigProtobuf::PrivateKey* curve25519_key = config->add_key();
  curve25519_key->set_tag(kC255);
  curve25519_key->set_private_key(curve25519_private_key);

  if (options.p256) {
    QuicServerConfigProtobuf::PrivateKey* p256_key = config->add_key();
    p256_key->set_tag(kP256);
    p256_key->set_private_key(p256_private_key);
  }

  return config.release();
}

CryptoHandshakeMessage* QuicCryptoServerConfig::AddConfig(
    QuicServerConfigProtobuf* protobuf,
    const QuicWallTime now) {
  std::unique_ptr<CryptoHandshakeMessage> msg(
      CryptoFramer::ParseMessage(protobuf->config()));

  if (!msg.get()) {
    LOG(WARNING) << "Failed to parse server config message";
    return nullptr;
  }

  scoped_refptr<Config> config(ParseConfigProtobuf(protobuf));
  if (!config.get()) {
    LOG(WARNING) << "Failed to parse server config message";
    return nullptr;
  }

  {
    base::AutoLock locked(configs_lock_);
    if (configs_.find(config->id) != configs_.end()) {
      LOG(WARNING) << "Failed to add config because another with the same "
                      "server config id already exists: "
                   << base::HexEncode(config->id.data(), config->id.size());
      return nullptr;
    }

    configs_[config->id] = config;
    SelectNewPrimaryConfig(now);
    DCHECK(primary_config_.get());
    DCHECK_EQ(configs_.find(primary_config_->id)->second, primary_config_);
  }

  return msg.release();
}

CryptoHandshakeMessage* QuicCryptoServerConfig::AddDefaultConfig(
    QuicRandom* rand,
    const QuicClock* clock,
    const ConfigOptions& options) {
  std::unique_ptr<QuicServerConfigProtobuf> config(
      GenerateConfig(rand, clock, options));
  return AddConfig(config.get(), clock->WallNow());
}

bool QuicCryptoServerConfig::SetConfigs(
    const vector<QuicServerConfigProtobuf*>& protobufs,
    const QuicWallTime now) {
  vector<scoped_refptr<Config>> parsed_configs;
  bool ok = true;

  for (vector<QuicServerConfigProtobuf*>::const_iterator i = protobufs.begin();
       i != protobufs.end(); ++i) {
    scoped_refptr<Config> config(ParseConfigProtobuf(*i));
    if (!config.get()) {
      ok = false;
      break;
    }

    parsed_configs.push_back(config);
  }

  if (parsed_configs.empty()) {
    LOG(WARNING) << "New config list is empty.";
    ok = false;
  }

  if (!ok) {
    LOG(WARNING) << "Rejecting QUIC configs because of above errors";
  } else {
    VLOG(1) << "Updating configs:";

    base::AutoLock locked(configs_lock_);
    ConfigMap new_configs;

    for (vector<scoped_refptr<Config>>::const_iterator i =
             parsed_configs.begin();
         i != parsed_configs.end(); ++i) {
      scoped_refptr<Config> config = *i;

      ConfigMap::iterator it = configs_.find(config->id);
      if (it != configs_.end()) {
        VLOG(1) << "Keeping scid: "
                << base::HexEncode(config->id.data(), config->id.size())
                << " orbit: "
                << base::HexEncode(reinterpret_cast<const char*>(config->orbit),
                                   kOrbitSize)
                << " new primary_time " << config->primary_time.ToUNIXSeconds()
                << " old primary_time "
                << it->second->primary_time.ToUNIXSeconds() << " new priority "
                << config->priority << " old priority " << it->second->priority;
        // Update primary_time and priority.
        it->second->primary_time = config->primary_time;
        it->second->priority = config->priority;
        new_configs.insert(*it);
      } else {
        VLOG(1) << "Adding scid: "
                << base::HexEncode(config->id.data(), config->id.size())
                << " orbit: "
                << base::HexEncode(reinterpret_cast<const char*>(config->orbit),
                                   kOrbitSize)
                << " primary_time " << config->primary_time.ToUNIXSeconds()
                << " priority " << config->priority;
        new_configs.insert(std::make_pair(config->id, config));
      }
    }

    configs_.swap(new_configs);
    SelectNewPrimaryConfig(now);
    DCHECK(primary_config_.get());
    DCHECK_EQ(configs_.find(primary_config_->id)->second, primary_config_);
  }

  return ok;
}

void QuicCryptoServerConfig::SetDefaultSourceAddressTokenKeys(
    const vector<string>& keys) {
  default_source_address_token_boxer_.SetKeys(keys);
}

void QuicCryptoServerConfig::GetConfigIds(vector<string>* scids) const {
  base::AutoLock locked(configs_lock_);
  for (ConfigMap::const_iterator it = configs_.begin(); it != configs_.end();
       ++it) {
    scids->push_back(it->first);
  }
}

void QuicCryptoServerConfig::ValidateClientHello(
    const CryptoHandshakeMessage& client_hello,
    const IPAddress& client_ip,
    const IPAddress& server_ip,
    QuicVersion version,
    const QuicClock* clock,
    QuicCryptoProof* crypto_proof,
    ValidateClientHelloResultCallback* done_cb) const {
  const QuicWallTime now(clock->WallNow());

  ValidateClientHelloResultCallback::Result* result =
      new ValidateClientHelloResultCallback::Result(client_hello, client_ip,
                                                    now);

  StringPiece requested_scid;
  client_hello.GetStringPiece(kSCID, &requested_scid);

  uint8_t primary_orbit[kOrbitSize];
  scoped_refptr<Config> requested_config;
  scoped_refptr<Config> primary_config;
  {
    base::AutoLock locked(configs_lock_);

    if (!primary_config_.get()) {
      result->error_code = QUIC_CRYPTO_INTERNAL_ERROR;
      result->error_details = "No configurations loaded";
    } else {
      if (!next_config_promotion_time_.IsZero() &&
          next_config_promotion_time_.IsAfter(now)) {
        SelectNewPrimaryConfig(now);
        DCHECK(primary_config_.get());
        DCHECK_EQ(configs_.find(primary_config_->id)->second, primary_config_);
      }

      memcpy(primary_orbit, primary_config_->orbit, sizeof(primary_orbit));
    }

    requested_config = GetConfigWithScid(requested_scid);
    primary_config = primary_config_;
    crypto_proof->config = primary_config_;
  }

  if (result->error_code == QUIC_NO_ERROR) {
    EvaluateClientHello(server_ip, version, primary_orbit, requested_config,
                        primary_config, crypto_proof, result, done_cb);
  } else {
    done_cb->Run(result);
  }
}

QuicErrorCode QuicCryptoServerConfig::ProcessClientHello(
    const ValidateClientHelloResultCallback::Result& validate_chlo_result,
    QuicConnectionId connection_id,
    const IPAddress& server_ip,
    const IPEndPoint& client_address,
    QuicVersion version,
    const QuicVersionVector& supported_versions,
    bool use_stateless_rejects,
    QuicConnectionId server_designated_connection_id,
    const QuicClock* clock,
    QuicRandom* rand,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicCryptoNegotiatedParameters* params,
    QuicCryptoProof* crypto_proof,
    CryptoHandshakeMessage* out,
    DiversificationNonce* out_diversification_nonce,
    string* error_details) const {
  DCHECK(error_details);

  const CryptoHandshakeMessage& client_hello =
      validate_chlo_result.client_hello;
  const ClientHelloInfo& info = validate_chlo_result.info;

  QuicErrorCode valid = CryptoUtils::ValidateClientHello(
      client_hello, version, supported_versions, error_details);
  if (valid != QUIC_NO_ERROR)
    return valid;

  StringPiece requested_scid;
  client_hello.GetStringPiece(kSCID, &requested_scid);
  const QuicWallTime now(clock->WallNow());

  scoped_refptr<Config> requested_config;
  scoped_refptr<Config> primary_config;
  {
    base::AutoLock locked(configs_lock_);

    if (!primary_config_.get()) {
      *error_details = "No configurations loaded";
      return QUIC_CRYPTO_INTERNAL_ERROR;
    }

    if (!next_config_promotion_time_.IsZero() &&
        next_config_promotion_time_.IsAfter(now)) {
      SelectNewPrimaryConfig(now);
      DCHECK(primary_config_.get());
      DCHECK_EQ(configs_.find(primary_config_->id)->second, primary_config_);
    }

    // Use the config that the client requested in order to do key-agreement.
    // Otherwise give it a copy of |primary_config_| to use.
    primary_config = crypto_proof->config;
    requested_config = GetConfigWithScid(requested_scid);
  }

  if (validate_chlo_result.error_code != QUIC_NO_ERROR) {
    *error_details = validate_chlo_result.error_details;
    return validate_chlo_result.error_code;
  }

  out->Clear();

  bool x509_supported = false;
  bool x509_ecdsa_supported = false;
  ParseProofDemand(client_hello, &x509_supported, &x509_ecdsa_supported);
  DCHECK(proof_source_.get());
  string chlo_hash;
  CryptoUtils::HashHandshakeMessage(client_hello, &chlo_hash);
  if (!crypto_proof->chain &&
      !proof_source_->GetProof(
          server_ip, info.sni.as_string(), primary_config->serialized, version,
          chlo_hash, x509_ecdsa_supported, &crypto_proof->chain,
          &crypto_proof->signature, &crypto_proof->cert_sct)) {
    return QUIC_HANDSHAKE_FAILED;
  }

  if (version > QUIC_VERSION_29) {
    StringPiece cert_sct;
    if (client_hello.GetStringPiece(kCertificateSCTTag, &cert_sct) &&
        cert_sct.empty()) {
      params->sct_supported_by_client = true;
    }
  }

  if (!info.reject_reasons.empty() || !requested_config.get()) {
    BuildRejection(version, *primary_config, client_hello, info,
                   validate_chlo_result.cached_network_params,
                   use_stateless_rejects, server_designated_connection_id, rand,
                   compressed_certs_cache, params, *crypto_proof, out);
    return QUIC_NO_ERROR;
  }

  const QuicTag* their_aeads;
  const QuicTag* their_key_exchanges;
  size_t num_their_aeads, num_their_key_exchanges;
  if (client_hello.GetTaglist(kAEAD, &their_aeads, &num_their_aeads) !=
          QUIC_NO_ERROR ||
      client_hello.GetTaglist(kKEXS, &their_key_exchanges,
                              &num_their_key_exchanges) != QUIC_NO_ERROR ||
      num_their_aeads != 1 || num_their_key_exchanges != 1) {
    *error_details = "Missing or invalid AEAD or KEXS";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  size_t key_exchange_index;
  if (!QuicUtils::FindMutualTag(requested_config->aead, their_aeads,
                                num_their_aeads, QuicUtils::LOCAL_PRIORITY,
                                &params->aead, nullptr) ||
      !QuicUtils::FindMutualTag(requested_config->kexs, their_key_exchanges,
                                num_their_key_exchanges,
                                QuicUtils::LOCAL_PRIORITY,
                                &params->key_exchange, &key_exchange_index)) {
    *error_details = "Unsupported AEAD or KEXS";
    return QUIC_CRYPTO_NO_SUPPORT;
  }

  if (!requested_config->tb_key_params.empty()) {
    const QuicTag* their_tbkps;
    size_t num_their_tbkps;
    switch (client_hello.GetTaglist(kTBKP, &their_tbkps, &num_their_tbkps)) {
      case QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND:
        break;
      case QUIC_NO_ERROR:
        if (QuicUtils::FindMutualTag(
                requested_config->tb_key_params, their_tbkps, num_their_tbkps,
                QuicUtils::LOCAL_PRIORITY, &params->token_binding_key_param,
                nullptr)) {
          break;
        }
      default:
        *error_details = "Invalid Token Binding key parameter";
        return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }
  }

  StringPiece public_value;
  if (!client_hello.GetStringPiece(kPUBS, &public_value)) {
    *error_details = "Missing public value";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  const KeyExchange* key_exchange =
      requested_config->key_exchanges[key_exchange_index];
  if (!key_exchange->CalculateSharedKey(public_value,
                                        &params->initial_premaster_secret)) {
    *error_details = "Invalid public value";
    return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
  }

  if (!info.sni.empty()) {
    std::unique_ptr<char[]> sni_tmp(new char[info.sni.length() + 1]);
    memcpy(sni_tmp.get(), info.sni.data(), info.sni.length());
    sni_tmp[info.sni.length()] = 0;
    params->sni = CryptoUtils::NormalizeHostname(sni_tmp.get());
  }

  string hkdf_suffix;
  const QuicData& client_hello_serialized = client_hello.GetSerialized();
  hkdf_suffix.reserve(sizeof(connection_id) + client_hello_serialized.length() +
                      requested_config->serialized.size());
  hkdf_suffix.append(reinterpret_cast<char*>(&connection_id),
                     sizeof(connection_id));
  hkdf_suffix.append(client_hello_serialized.data(),
                     client_hello_serialized.length());
  hkdf_suffix.append(requested_config->serialized);
  DCHECK(proof_source_.get());
  if (version > QUIC_VERSION_25) {
    if (crypto_proof->chain->certs.empty()) {
      *error_details = "Failed to get certs";
      return QUIC_CRYPTO_INTERNAL_ERROR;
    }
    hkdf_suffix.append(crypto_proof->chain->certs.at(0));
  }

  StringPiece cetv_ciphertext;
  if (requested_config->channel_id_enabled &&
      client_hello.GetStringPiece(kCETV, &cetv_ciphertext)) {
    CryptoHandshakeMessage client_hello_copy(client_hello);
    client_hello_copy.Erase(kCETV);
    client_hello_copy.Erase(kPAD);

    const QuicData& client_hello_copy_serialized =
        client_hello_copy.GetSerialized();
    string hkdf_input;
    hkdf_input.append(QuicCryptoConfig::kCETVLabel,
                      strlen(QuicCryptoConfig::kCETVLabel) + 1);
    hkdf_input.append(reinterpret_cast<char*>(&connection_id),
                      sizeof(connection_id));
    hkdf_input.append(client_hello_copy_serialized.data(),
                      client_hello_copy_serialized.length());
    hkdf_input.append(requested_config->serialized);

    CrypterPair crypters;
    if (!CryptoUtils::DeriveKeys(params->initial_premaster_secret, params->aead,
                                 info.client_nonce, info.server_nonce,
                                 hkdf_input, Perspective::IS_SERVER,
                                 CryptoUtils::Diversification::Never(),
                                 &crypters, nullptr /* subkey secret */)) {
      *error_details = "Symmetric key setup failed";
      return QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED;
    }

    char plaintext[kMaxPacketSize];
    size_t plaintext_length = 0;
    const bool success = crypters.decrypter->DecryptPacket(
        kDefaultPathId, 0 /* packet number */,
        StringPiece() /* associated data */, cetv_ciphertext, plaintext,
        &plaintext_length, kMaxPacketSize);
    if (!success) {
      *error_details = "CETV decryption failure";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }
    std::unique_ptr<CryptoHandshakeMessage> cetv(
        CryptoFramer::ParseMessage(StringPiece(plaintext, plaintext_length)));
    if (!cetv.get()) {
      *error_details = "CETV parse error";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }

    StringPiece key, signature;
    if (cetv->GetStringPiece(kCIDK, &key) &&
        cetv->GetStringPiece(kCIDS, &signature)) {
      if (!ChannelIDVerifier::Verify(key, hkdf_input, signature)) {
        *error_details = "ChannelID signature failure";
        return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
      }

      params->channel_id = key.as_string();
    }
  }

  string hkdf_input;
  size_t label_len = strlen(QuicCryptoConfig::kInitialLabel) + 1;
  hkdf_input.reserve(label_len + hkdf_suffix.size());
  hkdf_input.append(QuicCryptoConfig::kInitialLabel, label_len);
  hkdf_input.append(hkdf_suffix);

  string* subkey_secret = &params->initial_subkey_secret;
  CryptoUtils::Diversification diversification =
      CryptoUtils::Diversification::Never();
  if (version > QUIC_VERSION_32) {
    rand->RandBytes(reinterpret_cast<char*>(out_diversification_nonce),
                    sizeof(*out_diversification_nonce));
    diversification =
        CryptoUtils::Diversification::Now(out_diversification_nonce);
  }

  if (!CryptoUtils::DeriveKeys(params->initial_premaster_secret, params->aead,
                               info.client_nonce, info.server_nonce, hkdf_input,
                               Perspective::IS_SERVER, diversification,
                               &params->initial_crypters, subkey_secret)) {
    *error_details = "Symmetric key setup failed";
    return QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED;
  }

  string forward_secure_public_value;
  if (ephemeral_key_source_.get()) {
    params->forward_secure_premaster_secret =
        ephemeral_key_source_->CalculateForwardSecureKey(
            key_exchange, rand, clock->ApproximateNow(), public_value,
            &forward_secure_public_value);
  } else {
    std::unique_ptr<KeyExchange> forward_secure_key_exchange(
        key_exchange->NewKeyPair(rand));
    forward_secure_public_value =
        forward_secure_key_exchange->public_value().as_string();
    if (!forward_secure_key_exchange->CalculateSharedKey(
            public_value, &params->forward_secure_premaster_secret)) {
      *error_details = "Invalid public value";
      return QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER;
    }
  }

  string forward_secure_hkdf_input;
  label_len = strlen(QuicCryptoConfig::kForwardSecureLabel) + 1;
  forward_secure_hkdf_input.reserve(label_len + hkdf_suffix.size());
  forward_secure_hkdf_input.append(QuicCryptoConfig::kForwardSecureLabel,
                                   label_len);
  forward_secure_hkdf_input.append(hkdf_suffix);

  string shlo_nonce;
  if (version > QUIC_VERSION_26) {
    shlo_nonce = NewServerNonce(rand, info.now);
    out->SetStringPiece(kServerNonceTag, shlo_nonce);
  }

  if (!CryptoUtils::DeriveKeys(
          params->forward_secure_premaster_secret, params->aead,
          info.client_nonce,
          shlo_nonce.empty() ? info.server_nonce : shlo_nonce,
          forward_secure_hkdf_input, Perspective::IS_SERVER,
          CryptoUtils::Diversification::Never(),
          &params->forward_secure_crypters, &params->subkey_secret)) {
    *error_details = "Symmetric key setup failed";
    return QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED;
  }

  out->set_tag(kSHLO);
  QuicTagVector supported_version_tags;
  for (size_t i = 0; i < supported_versions.size(); ++i) {
    supported_version_tags.push_back(
        QuicVersionToQuicTag(supported_versions[i]));
  }
  out->SetVector(kVER, supported_version_tags);
  out->SetStringPiece(
      kSourceAddressTokenTag,
      NewSourceAddressToken(*requested_config.get(), info.source_address_tokens,
                            client_address.address(), rand, info.now, nullptr));
  QuicSocketAddressCoder address_coder(client_address);
  out->SetStringPiece(kCADR, address_coder.Encode());
  out->SetStringPiece(kPUBS, forward_secure_public_value);

  return QUIC_NO_ERROR;
}

scoped_refptr<QuicCryptoServerConfig::Config>
QuicCryptoServerConfig::GetConfigWithScid(StringPiece requested_scid) const {
  // In Chromium, we will dead lock if the lock is held by the current thread.
  // Chromium doesn't have AssertReaderHeld API call.
  // configs_lock_.AssertReaderHeld();

  if (!requested_scid.empty()) {
    ConfigMap::const_iterator it = configs_.find(requested_scid.as_string());
    if (it != configs_.end()) {
      // We'll use the config that the client requested in order to do
      // key-agreement.
      return scoped_refptr<Config>(it->second);
    }
  }

  return scoped_refptr<Config>();
}

// ConfigPrimaryTimeLessThan is a comparator that implements "less than" for
// Config's based on their primary_time.
// static
bool QuicCryptoServerConfig::ConfigPrimaryTimeLessThan(
    const scoped_refptr<Config>& a,
    const scoped_refptr<Config>& b) {
  if (a->primary_time.IsBefore(b->primary_time) ||
      b->primary_time.IsBefore(a->primary_time)) {
    // Primary times differ.
    return a->primary_time.IsBefore(b->primary_time);
  } else if (a->priority != b->priority) {
    // Primary times are equal, sort backwards by priority.
    return a->priority < b->priority;
  } else {
    // Primary times and priorities are equal, sort by config id.
    return a->id < b->id;
  }
}

void QuicCryptoServerConfig::SelectNewPrimaryConfig(
    const QuicWallTime now) const {
  vector<scoped_refptr<Config>> configs;
  configs.reserve(configs_.size());

  for (ConfigMap::const_iterator it = configs_.begin(); it != configs_.end();
       ++it) {
    // TODO(avd) Exclude expired configs?
    configs.push_back(it->second);
  }

  if (configs.empty()) {
    if (primary_config_.get()) {
      QUIC_BUG << "No valid QUIC server config. Keeping the current config.";
    } else {
      QUIC_BUG << "No valid QUIC server config.";
    }
    return;
  }

  std::sort(configs.begin(), configs.end(), ConfigPrimaryTimeLessThan);

  Config* best_candidate = configs[0].get();

  for (size_t i = 0; i < configs.size(); ++i) {
    const scoped_refptr<Config> config(configs[i]);
    if (!config->primary_time.IsAfter(now)) {
      if (config->primary_time.IsAfter(best_candidate->primary_time)) {
        best_candidate = config.get();
      }
      continue;
    }

    // This is the first config with a primary_time in the future. Thus the
    // previous Config should be the primary and this one should determine the
    // next_config_promotion_time_.
    scoped_refptr<Config> new_primary(best_candidate);
    if (i == 0) {
      // We need the primary_time of the next config.
      if (configs.size() > 1) {
        next_config_promotion_time_ = configs[1]->primary_time;
      } else {
        next_config_promotion_time_ = QuicWallTime::Zero();
      }
    } else {
      next_config_promotion_time_ = config->primary_time;
    }

    if (primary_config_.get()) {
      primary_config_->is_primary = false;
    }
    primary_config_ = new_primary;
    new_primary->is_primary = true;
    DVLOG(1) << "New primary config.  orbit: "
             << base::HexEncode(
                    reinterpret_cast<const char*>(primary_config_->orbit),
                    kOrbitSize);
    if (primary_config_changed_cb_.get() != nullptr) {
      primary_config_changed_cb_->Run(primary_config_->id);
    }

    return;
  }

  // All config's primary times are in the past. We should make the most recent
  // and highest priority candidate primary.
  scoped_refptr<Config> new_primary(best_candidate);
  if (primary_config_.get()) {
    primary_config_->is_primary = false;
  }
  primary_config_ = new_primary;
  new_primary->is_primary = true;
  DVLOG(1) << "New primary config.  orbit: "
           << base::HexEncode(
                  reinterpret_cast<const char*>(primary_config_->orbit),
                  kOrbitSize)
           << " scid: " << base::HexEncode(primary_config_->id.data(),
                                           primary_config_->id.size());
  next_config_promotion_time_ = QuicWallTime::Zero();
  if (primary_config_changed_cb_.get() != nullptr) {
    primary_config_changed_cb_->Run(primary_config_->id);
  }
}

void QuicCryptoServerConfig::EvaluateClientHello(
    const IPAddress& server_ip,
    QuicVersion version,
    const uint8_t* primary_orbit,
    scoped_refptr<Config> requested_config,
    scoped_refptr<Config> primary_config,
    QuicCryptoProof* crypto_proof,
    ValidateClientHelloResultCallback::Result* client_hello_state,
    ValidateClientHelloResultCallback* done_cb) const {
  ValidateClientHelloHelper helper(client_hello_state, done_cb);

  const CryptoHandshakeMessage& client_hello = client_hello_state->client_hello;
  ClientHelloInfo* info = &(client_hello_state->info);

  if (client_hello.size() < kClientHelloMinimumSize) {
    helper.ValidationComplete(QUIC_CRYPTO_INVALID_VALUE_LENGTH,
                              "Client hello too small");
    return;
  }

  if (client_hello.GetStringPiece(kSNI, &info->sni) &&
      !CryptoUtils::IsValidSNI(info->sni)) {
    helper.ValidationComplete(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER,
                              "Invalid SNI name");
    return;
  }

  client_hello.GetStringPiece(kUAID, &info->user_agent_id);

  HandshakeFailureReason source_address_token_error = MAX_FAILURE_REASON;
  StringPiece srct;
  if (client_hello.GetStringPiece(kSourceAddressTokenTag, &srct)) {
    Config& config =
        requested_config != nullptr ? *requested_config : *primary_config;
    source_address_token_error =
        ParseSourceAddressToken(config, srct, &info->source_address_tokens);

    if (source_address_token_error == HANDSHAKE_OK) {
      source_address_token_error = ValidateSourceAddressTokens(
          info->source_address_tokens, info->client_ip, info->now,
          &client_hello_state->cached_network_params);
    }
    info->valid_source_address_token =
        (source_address_token_error == HANDSHAKE_OK);
  } else {
    source_address_token_error = SOURCE_ADDRESS_TOKEN_INVALID_FAILURE;
  }

  if (!requested_config.get()) {
    StringPiece requested_scid;
    if (client_hello.GetStringPiece(kSCID, &requested_scid)) {
      info->reject_reasons.push_back(SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE);
    } else {
      info->reject_reasons.push_back(SERVER_CONFIG_INCHOATE_HELLO_FAILURE);
    }
    // No server config with the requested ID.
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  if (!client_hello.GetStringPiece(kNONC, &info->client_nonce)) {
    info->reject_reasons.push_back(SERVER_CONFIG_INCHOATE_HELLO_FAILURE);
    // Report no client nonce as INCHOATE_HELLO_FAILURE.
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  bool found_error = false;
  if (source_address_token_error != HANDSHAKE_OK) {
    info->reject_reasons.push_back(source_address_token_error);
    // No valid source address token.
    if (FLAGS_use_early_return_when_verifying_chlo) {
      helper.ValidationComplete(QUIC_NO_ERROR, "");
      return;
    }
    found_error = true;
  }

  if (version > QUIC_VERSION_25) {
    bool x509_supported = false;
    bool x509_ecdsa_supported = false;
    ParseProofDemand(client_hello, &x509_supported, &x509_ecdsa_supported);
    string serialized_config = primary_config->serialized;
    string chlo_hash;
    CryptoUtils::HashHandshakeMessage(client_hello, &chlo_hash);
    if (!proof_source_->GetProof(
            server_ip, info->sni.as_string(), serialized_config, version,
            chlo_hash, x509_ecdsa_supported, &crypto_proof->chain,
            &crypto_proof->signature, &crypto_proof->cert_sct)) {
      found_error = true;
      info->reject_reasons.push_back(SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE);
    }

    if (!ValidateExpectedLeafCertificate(client_hello, *crypto_proof)) {
      found_error = true;
      info->reject_reasons.push_back(INVALID_EXPECTED_LEAF_CERTIFICATE);
    }
  }

  if (info->client_nonce.size() != kNonceSize) {
    info->reject_reasons.push_back(CLIENT_NONCE_INVALID_FAILURE);
    // Invalid client nonce.
    LOG(ERROR) << "Invalid client nonce: " << client_hello.DebugString();
    DVLOG(1) << "Invalid client nonce.";
    if (FLAGS_use_early_return_when_verifying_chlo) {
      helper.ValidationComplete(QUIC_NO_ERROR, "");
      return;
    }
    found_error = true;
  }

  // Server nonce is optional, and used for key derivation if present.
  client_hello.GetStringPiece(kServerNonceTag, &info->server_nonce);

  if (version > QUIC_VERSION_32) {
    DVLOG(1) << "No 0-RTT replay protection in QUIC_VERSION_33 and higher.";
    // If the server nonce is empty and we're requiring handshake confirmation
    // for DoS reasons then we must reject the CHLO.
    if (FLAGS_quic_require_handshake_confirmation &&
        info->server_nonce.empty()) {
      info->reject_reasons.push_back(SERVER_NONCE_REQUIRED_FAILURE);
    }
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  if (!replay_protection_) {
    DVLOG(1) << "No replay protection.";
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  if (!info->server_nonce.empty()) {
    // If the server nonce is present, use it to establish uniqueness.
    HandshakeFailureReason server_nonce_error =
        ValidateServerNonce(info->server_nonce, info->now);
    bool is_unique = server_nonce_error == HANDSHAKE_OK;
    if (!is_unique) {
      info->reject_reasons.push_back(server_nonce_error);
    }
    DVLOG(1) << "Using server nonce, unique: " << is_unique;
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }
  // If we hit this block, the server nonce was empty.  If we're requiring
  // handshake confirmation for DoS reasons and there's no server nonce present,
  // reject the CHLO.
  if (FLAGS_quic_require_handshake_confirmation) {
    info->reject_reasons.push_back(SERVER_NONCE_REQUIRED_FAILURE);
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  // We want to contact strike register only if there are no errors because it
  // is a RPC call and is expensive.
  if (found_error) {
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  // Use the client nonce to establish uniqueness.
  StrikeRegisterClient* strike_register_client;
  {
    base::AutoLock locked(strike_register_client_lock_);
    strike_register_client = strike_register_client_.get();
  }

  if (!strike_register_client) {
    // Either a valid server nonces or a strike register is required.
    // Since neither are present, reject the handshake which will send a
    // server nonce to the client.
    info->reject_reasons.push_back(SERVER_NONCE_REQUIRED_FAILURE);
    helper.ValidationComplete(QUIC_NO_ERROR, "");
    return;
  }

  strike_register_client->VerifyNonceIsValidAndUnique(
      info->client_nonce, info->now,
      new VerifyNonceIsValidAndUniqueCallback(client_hello_state, done_cb));
  helper.StartedAsyncCallback();
}

bool QuicCryptoServerConfig::BuildServerConfigUpdateMessage(
    QuicVersion version,
    const SourceAddressTokens& previous_source_address_tokens,
    const IPAddress& server_ip,
    const IPAddress& client_ip,
    const QuicClock* clock,
    QuicRandom* rand,
    QuicCompressedCertsCache* compressed_certs_cache,
    const QuicCryptoNegotiatedParameters& params,
    const CachedNetworkParameters* cached_network_params,
    CryptoHandshakeMessage* out) const {
  base::AutoLock locked(configs_lock_);
  out->set_tag(kSCUP);
  out->SetStringPiece(kSCFG, primary_config_->serialized);
  out->SetStringPiece(
      kSourceAddressTokenTag,
      NewSourceAddressToken(*primary_config_.get(),
                            previous_source_address_tokens, client_ip, rand,
                            clock->WallNow(), cached_network_params));

  scoped_refptr<ProofSource::Chain> chain;
  string signature;
  string cert_sct;
  if (!proof_source_->GetProof(server_ip, params.sni,
                               primary_config_->serialized, version,
                               params.client_nonce, params.x509_ecdsa_supported,
                               &chain, &signature, &cert_sct)) {
    DVLOG(1) << "Server: failed to get proof.";
    return false;
  }

  const string compressed = CompressChain(
      compressed_certs_cache, chain, params.client_common_set_hashes,
      params.client_cached_cert_hashes, primary_config_->common_cert_sets);

  out->SetStringPiece(kCertificateTag, compressed);
  out->SetStringPiece(kPROF, signature);
  if (params.sct_supported_by_client && version > QUIC_VERSION_29 &&
      enable_serving_sct_) {
    if (cert_sct.empty()) {
      DLOG(WARNING) << "SCT is expected but it is empty.";
    } else {
      out->SetStringPiece(kCertificateSCTTag, cert_sct);
    }
  }
  return true;
}

void QuicCryptoServerConfig::BuildRejection(
    QuicVersion version,
    const Config& config,
    const CryptoHandshakeMessage& client_hello,
    const ClientHelloInfo& info,
    const CachedNetworkParameters& cached_network_params,
    bool use_stateless_rejects,
    QuicConnectionId server_designated_connection_id,
    QuicRandom* rand,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicCryptoNegotiatedParameters* params,
    const QuicCryptoProof& crypto_proof,
    CryptoHandshakeMessage* out) const {
  if (FLAGS_enable_quic_stateless_reject_support && use_stateless_rejects) {
    DVLOG(1) << "QUIC Crypto server config returning stateless reject "
             << "with server-designated connection ID "
             << server_designated_connection_id;
    out->set_tag(kSREJ);
    out->SetValue(kRCID, server_designated_connection_id);
  } else {
    out->set_tag(kREJ);
  }
  out->SetStringPiece(kSCFG, config.serialized);
  out->SetStringPiece(
      kSourceAddressTokenTag,
      NewSourceAddressToken(config, info.source_address_tokens, info.client_ip,
                            rand, info.now, &cached_network_params));
  if (replay_protection_) {
    out->SetStringPiece(kServerNonceTag, NewServerNonce(rand, info.now));
  }

  // Send client the reject reason for debugging purposes.
  DCHECK_LT(0u, info.reject_reasons.size());
  out->SetVector(kRREJ, info.reject_reasons);

  // The client may have requested a certificate chain.
  bool x509_supported = false;
  ParseProofDemand(client_hello, &x509_supported,
                   &params->x509_ecdsa_supported);
  if (!x509_supported) {
    return;
  }

  StringPiece client_common_set_hashes;
  if (client_hello.GetStringPiece(kCCS, &client_common_set_hashes)) {
    params->client_common_set_hashes = client_common_set_hashes.as_string();
  }

  StringPiece client_cached_cert_hashes;
  if (client_hello.GetStringPiece(kCCRT, &client_cached_cert_hashes)) {
    params->client_cached_cert_hashes = client_cached_cert_hashes.as_string();
  }

  const string compressed =
      CompressChain(compressed_certs_cache, crypto_proof.chain,
                    params->client_common_set_hashes,
                    params->client_cached_cert_hashes, config.common_cert_sets);

  // kREJOverheadBytes is a very rough estimate of how much of a REJ
  // message is taken up by things other than the certificates.
  // STK: 56 bytes
  // SNO: 56 bytes
  // SCFG
  //   SCID: 16 bytes
  //   PUBS: 38 bytes
  const size_t kREJOverheadBytes = 166;
  // max_unverified_size is the number of bytes that the certificate chain,
  // signature, and (optionally) signed certificate timestamp can consume before
  // we will demand a valid source-address token.
  const size_t max_unverified_size =
      client_hello.size() * chlo_multiplier_ - kREJOverheadBytes;
  static_assert(kClientHelloMinimumSize * kMultiplier >= kREJOverheadBytes,
                "overhead calculation may underflow");
  bool should_return_sct = params->sct_supported_by_client &&
                           version > QUIC_VERSION_29 && enable_serving_sct_;
  const size_t sct_size = should_return_sct ? crypto_proof.cert_sct.size() : 0;
  if (info.valid_source_address_token ||
      crypto_proof.signature.size() + compressed.size() + sct_size <
          max_unverified_size) {
    out->SetStringPiece(kCertificateTag, compressed);
    out->SetStringPiece(kPROF, crypto_proof.signature);
    if (should_return_sct) {
      if (crypto_proof.cert_sct.empty()) {
        DLOG(WARNING) << "SCT is expected but it is empty.";
      } else {
        out->SetStringPiece(kCertificateSCTTag, crypto_proof.cert_sct);
      }
    }
  }
}

const string QuicCryptoServerConfig::CompressChain(
    QuicCompressedCertsCache* compressed_certs_cache,
    const scoped_refptr<ProofSource::Chain>& chain,
    const string& client_common_set_hashes,
    const string& client_cached_cert_hashes,
    const CommonCertSets* common_sets) const {
  // Check whether the compressed certs is available in the cache.
  DCHECK(compressed_certs_cache);
  const string* cached_value = compressed_certs_cache->GetCompressedCert(
      chain, client_common_set_hashes, client_cached_cert_hashes);
  if (cached_value) {
    return *cached_value;
  }

  const string compressed =
      CertCompressor::CompressChain(chain->certs, client_common_set_hashes,
                                    client_common_set_hashes, common_sets);

  // Insert the newly compressed cert to cache.
  compressed_certs_cache->Insert(chain, client_common_set_hashes,
                                 client_cached_cert_hashes, compressed);
  return compressed;
}

scoped_refptr<QuicCryptoServerConfig::Config>
QuicCryptoServerConfig::ParseConfigProtobuf(
    QuicServerConfigProtobuf* protobuf) {
  std::unique_ptr<CryptoHandshakeMessage> msg(
      CryptoFramer::ParseMessage(protobuf->config()));

  if (msg->tag() != kSCFG) {
    LOG(WARNING) << "Server config message has tag " << msg->tag()
                 << " expected " << kSCFG;
    return nullptr;
  }

  scoped_refptr<Config> config(new Config);
  config->serialized = protobuf->config();

  if (!protobuf->has_source_address_token_secret_override()) {
    // Use the default boxer.
    config->source_address_token_boxer = &default_source_address_token_boxer_;
  } else {
    // Create override boxer instance.
    CryptoSecretBoxer* boxer = new CryptoSecretBoxer;
    boxer->SetKeys({DeriveSourceAddressTokenKey(
        protobuf->source_address_token_secret_override())});
    config->source_address_token_boxer_storage.reset(boxer);
    config->source_address_token_boxer = boxer;
  }

  if (protobuf->has_primary_time()) {
    config->primary_time =
        QuicWallTime::FromUNIXSeconds(protobuf->primary_time());
  }

  config->priority = protobuf->priority();

  StringPiece scid;
  if (!msg->GetStringPiece(kSCID, &scid)) {
    LOG(WARNING) << "Server config message is missing SCID";
    return nullptr;
  }
  config->id = scid.as_string();

  const QuicTag* aead_tags;
  size_t aead_len;
  if (msg->GetTaglist(kAEAD, &aead_tags, &aead_len) != QUIC_NO_ERROR) {
    LOG(WARNING) << "Server config message is missing AEAD";
    return nullptr;
  }
  config->aead = vector<QuicTag>(aead_tags, aead_tags + aead_len);

  const QuicTag* kexs_tags;
  size_t kexs_len;
  if (msg->GetTaglist(kKEXS, &kexs_tags, &kexs_len) != QUIC_NO_ERROR) {
    LOG(WARNING) << "Server config message is missing KEXS";
    return nullptr;
  }

  const QuicTag* tbkp_tags;
  size_t tbkp_len;
  QuicErrorCode err;
  if ((err = msg->GetTaglist(kTBKP, &tbkp_tags, &tbkp_len)) !=
          QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND &&
      err != QUIC_NO_ERROR) {
    LOG(WARNING) << "Server config message is missing or has invalid TBKP";
    return nullptr;
  }
  config->tb_key_params = vector<QuicTag>(tbkp_tags, tbkp_tags + tbkp_len);

  StringPiece orbit;
  if (!msg->GetStringPiece(kORBT, &orbit)) {
    LOG(WARNING) << "Server config message is missing ORBT";
    return nullptr;
  }

  if (orbit.size() != kOrbitSize) {
    LOG(WARNING) << "Orbit value in server config is the wrong length."
                    " Got "
                 << orbit.size() << " want " << kOrbitSize;
    return nullptr;
  }
  static_assert(sizeof(config->orbit) == kOrbitSize,
                "orbit has incorrect size");
  memcpy(config->orbit, orbit.data(), sizeof(config->orbit));

  {
    StrikeRegisterClient* strike_register_client;
    {
      base::AutoLock locked(strike_register_client_lock_);
      strike_register_client = strike_register_client_.get();
    }

    if (strike_register_client != nullptr &&
        !strike_register_client->IsKnownOrbit(orbit)) {
      LOG(WARNING)
          << "Rejecting server config with orbit that the strike register "
             "client doesn't know about.";
      return nullptr;
    }
  }

  if (kexs_len != protobuf->key_size()) {
    LOG(WARNING) << "Server config has " << kexs_len
                 << " key exchange methods configured, but "
                 << protobuf->key_size() << " private keys";
    return nullptr;
  }

  const QuicTag* proof_demand_tags;
  size_t num_proof_demand_tags;
  if (msg->GetTaglist(kPDMD, &proof_demand_tags, &num_proof_demand_tags) ==
      QUIC_NO_ERROR) {
    for (size_t i = 0; i < num_proof_demand_tags; i++) {
      if (proof_demand_tags[i] == kCHID) {
        config->channel_id_enabled = true;
        break;
      }
    }
  }

  for (size_t i = 0; i < kexs_len; i++) {
    const QuicTag tag = kexs_tags[i];
    string private_key;

    config->kexs.push_back(tag);

    for (size_t j = 0; j < protobuf->key_size(); j++) {
      const QuicServerConfigProtobuf::PrivateKey& key = protobuf->key(i);
      if (key.tag() == tag) {
        private_key = key.private_key();
        break;
      }
    }

    if (private_key.empty()) {
      LOG(WARNING) << "Server config contains key exchange method without "
                      "corresponding private key: "
                   << tag;
      return nullptr;
    }

    std::unique_ptr<KeyExchange> ka;
    switch (tag) {
      case kC255:
        ka.reset(Curve25519KeyExchange::New(private_key));
        if (!ka.get()) {
          LOG(WARNING) << "Server config contained an invalid curve25519"
                          " private key.";
          return nullptr;
        }
        break;
      case kP256:
        ka.reset(P256KeyExchange::New(private_key));
        if (!ka.get()) {
          LOG(WARNING) << "Server config contained an invalid P-256"
                          " private key.";
          return nullptr;
        }
        break;
      default:
        LOG(WARNING) << "Server config message contains unknown key exchange "
                        "method: "
                     << tag;
        return nullptr;
    }

    for (const KeyExchange* key_exchange : config->key_exchanges) {
      if (key_exchange->tag() == tag) {
        LOG(WARNING) << "Duplicate key exchange in config: " << tag;
        return nullptr;
      }
    }

    config->key_exchanges.push_back(ka.release());
  }

  return config;
}

void QuicCryptoServerConfig::SetEphemeralKeySource(
    EphemeralKeySource* ephemeral_key_source) {
  ephemeral_key_source_.reset(ephemeral_key_source);
}

void QuicCryptoServerConfig::SetStrikeRegisterClient(
    StrikeRegisterClient* strike_register_client) {
  base::AutoLock locker(strike_register_client_lock_);
  DCHECK(!strike_register_client_.get());
  strike_register_client_.reset(strike_register_client);
}

void QuicCryptoServerConfig::set_replay_protection(bool on) {
  replay_protection_ = on;
}

void QuicCryptoServerConfig::set_chlo_multiplier(size_t multiplier) {
  chlo_multiplier_ = multiplier;
}

void QuicCryptoServerConfig::set_strike_register_no_startup_period() {
  base::AutoLock locker(strike_register_client_lock_);
  DCHECK(!strike_register_client_.get());
  strike_register_no_startup_period_ = true;
}

void QuicCryptoServerConfig::set_strike_register_max_entries(
    uint32_t max_entries) {
  base::AutoLock locker(strike_register_client_lock_);
  DCHECK(!strike_register_client_.get());
  strike_register_max_entries_ = max_entries;
}

void QuicCryptoServerConfig::set_strike_register_window_secs(
    uint32_t window_secs) {
  base::AutoLock locker(strike_register_client_lock_);
  DCHECK(!strike_register_client_.get());
  strike_register_window_secs_ = window_secs;
}

void QuicCryptoServerConfig::set_source_address_token_future_secs(
    uint32_t future_secs) {
  source_address_token_future_secs_ = future_secs;
}

void QuicCryptoServerConfig::set_source_address_token_lifetime_secs(
    uint32_t lifetime_secs) {
  source_address_token_lifetime_secs_ = lifetime_secs;
}

void QuicCryptoServerConfig::set_server_nonce_strike_register_max_entries(
    uint32_t max_entries) {
  DCHECK(!server_nonce_strike_register_.get());
  server_nonce_strike_register_max_entries_ = max_entries;
}

void QuicCryptoServerConfig::set_server_nonce_strike_register_window_secs(
    uint32_t window_secs) {
  DCHECK(!server_nonce_strike_register_.get());
  server_nonce_strike_register_window_secs_ = window_secs;
}

void QuicCryptoServerConfig::set_enable_serving_sct(bool enable_serving_sct) {
  enable_serving_sct_ = enable_serving_sct;
}

void QuicCryptoServerConfig::AcquirePrimaryConfigChangedCb(
    PrimaryConfigChangedCallback* cb) {
  base::AutoLock locked(configs_lock_);
  primary_config_changed_cb_.reset(cb);
}

string QuicCryptoServerConfig::NewSourceAddressToken(
    const Config& config,
    const SourceAddressTokens& previous_tokens,
    const IPAddress& ip,
    QuicRandom* rand,
    QuicWallTime now,
    const CachedNetworkParameters* cached_network_params) const {
  SourceAddressTokens source_address_tokens;
  SourceAddressToken* source_address_token = source_address_tokens.add_tokens();
  source_address_token->set_ip(IPAddressToPackedString(DualstackIPAddress(ip)));
  source_address_token->set_timestamp(now.ToUNIXSeconds());
  if (cached_network_params != nullptr) {
    *(source_address_token->mutable_cached_network_parameters()) =
        *cached_network_params;
  }

  // Append previous tokens.
  for (const SourceAddressToken& token : previous_tokens.tokens()) {
    if (source_address_tokens.tokens_size() > kMaxTokenAddresses) {
      break;
    }

    if (token.ip() == source_address_token->ip()) {
      // It's for the same IP address.
      continue;
    }

    if (ValidateSourceAddressTokenTimestamp(token, now) != HANDSHAKE_OK) {
      continue;
    }

    *(source_address_tokens.add_tokens()) = token;
  }

  return config.source_address_token_boxer->Box(
      rand, source_address_tokens.SerializeAsString());
}

int QuicCryptoServerConfig::NumberOfConfigs() const {
  base::AutoLock locked(configs_lock_);
  return configs_.size();
}

HandshakeFailureReason QuicCryptoServerConfig::ParseSourceAddressToken(
    const Config& config,
    StringPiece token,
    SourceAddressTokens* tokens) const {
  string storage;
  StringPiece plaintext;
  if (!config.source_address_token_boxer->Unbox(token, &storage, &plaintext)) {
    return SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE;
  }

  if (!tokens->ParseFromArray(plaintext.data(), plaintext.size())) {
    // Some clients might still be using the old source token format so
    // attempt to parse that format.
    // TODO(rch): remove this code once the new format is ubiquitous.
    SourceAddressToken source_address_token;
    if (!source_address_token.ParseFromArray(plaintext.data(),
                                             plaintext.size())) {
      return SOURCE_ADDRESS_TOKEN_PARSE_FAILURE;
    }
    *tokens->add_tokens() = source_address_token;
  }

  return HANDSHAKE_OK;
}

HandshakeFailureReason QuicCryptoServerConfig::ValidateSourceAddressTokens(
    const SourceAddressTokens& source_address_tokens,
    const IPAddress& ip,
    QuicWallTime now,
    CachedNetworkParameters* cached_network_params) const {
  HandshakeFailureReason reason =
      SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE;
  for (const SourceAddressToken& token : source_address_tokens.tokens()) {
    reason = ValidateSingleSourceAddressToken(token, ip, now);
    if (reason == HANDSHAKE_OK) {
      if (token.has_cached_network_parameters()) {
        *cached_network_params = token.cached_network_parameters();
      }
      break;
    }
  }
  return reason;
}

HandshakeFailureReason QuicCryptoServerConfig::ValidateSingleSourceAddressToken(
    const SourceAddressToken& source_address_token,
    const IPAddress& ip,
    QuicWallTime now) const {
  if (source_address_token.ip() !=
      IPAddressToPackedString(DualstackIPAddress(ip))) {
    // It's for a different IP address.
    return SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE;
  }

  return ValidateSourceAddressTokenTimestamp(source_address_token, now);
}

HandshakeFailureReason
QuicCryptoServerConfig::ValidateSourceAddressTokenTimestamp(
    const SourceAddressToken& source_address_token,
    QuicWallTime now) const {
  const QuicWallTime timestamp(
      QuicWallTime::FromUNIXSeconds(source_address_token.timestamp()));
  const QuicTime::Delta delta(now.AbsoluteDifference(timestamp));

  if (now.IsBefore(timestamp) &&
      delta.ToSeconds() > source_address_token_future_secs_) {
    return SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE;
  }

  if (now.IsAfter(timestamp) &&
      delta.ToSeconds() > source_address_token_lifetime_secs_) {
    return SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE;
  }

  return HANDSHAKE_OK;
}

// kServerNoncePlaintextSize is the number of bytes in an unencrypted server
// nonce.
static const size_t kServerNoncePlaintextSize =
    4 /* timestamp */ + 20 /* random bytes */;

string QuicCryptoServerConfig::NewServerNonce(QuicRandom* rand,
                                              QuicWallTime now) const {
  const uint32_t timestamp = static_cast<uint32_t>(now.ToUNIXSeconds());

  uint8_t server_nonce[kServerNoncePlaintextSize];
  static_assert(sizeof(server_nonce) > sizeof(timestamp), "nonce too small");
  server_nonce[0] = static_cast<uint8_t>(timestamp >> 24);
  server_nonce[1] = static_cast<uint8_t>(timestamp >> 16);
  server_nonce[2] = static_cast<uint8_t>(timestamp >> 8);
  server_nonce[3] = static_cast<uint8_t>(timestamp);
  rand->RandBytes(&server_nonce[sizeof(timestamp)],
                  sizeof(server_nonce) - sizeof(timestamp));

  return server_nonce_boxer_.Box(
      rand,
      StringPiece(reinterpret_cast<char*>(server_nonce), sizeof(server_nonce)));
}

HandshakeFailureReason QuicCryptoServerConfig::ValidateServerNonce(
    StringPiece token,
    QuicWallTime now) const {
  string storage;
  StringPiece plaintext;
  if (!server_nonce_boxer_.Unbox(token, &storage, &plaintext)) {
    return SERVER_NONCE_DECRYPTION_FAILURE;
  }

  // plaintext contains:
  //   uint32_t timestamp
  //   uint8_t[20] random bytes

  if (plaintext.size() != kServerNoncePlaintextSize) {
    // This should never happen because the value decrypted correctly.
    QUIC_BUG << "Seemingly valid server nonce had incorrect length.";
    return SERVER_NONCE_INVALID_FAILURE;
  }

  uint8_t server_nonce[32];
  memcpy(server_nonce, plaintext.data(), 4);
  memcpy(server_nonce + 4, server_nonce_orbit_, sizeof(server_nonce_orbit_));
  memcpy(server_nonce + 4 + sizeof(server_nonce_orbit_), plaintext.data() + 4,
         20);
  static_assert(4 + sizeof(server_nonce_orbit_) + 20 == sizeof(server_nonce),
                "bad nonce buffer length");

  InsertStatus nonce_error;
  {
    base::AutoLock auto_lock(server_nonce_strike_register_lock_);
    if (server_nonce_strike_register_.get() == nullptr) {
      server_nonce_strike_register_.reset(new StrikeRegister(
          server_nonce_strike_register_max_entries_,
          static_cast<uint32_t>(now.ToUNIXSeconds()),
          server_nonce_strike_register_window_secs_, server_nonce_orbit_,
          StrikeRegister::NO_STARTUP_PERIOD_NEEDED));
    }
    nonce_error = server_nonce_strike_register_->Insert(
        server_nonce, static_cast<uint32_t>(now.ToUNIXSeconds()));
  }

  switch (nonce_error) {
    case NONCE_OK:
      return HANDSHAKE_OK;
    case NONCE_INVALID_FAILURE:
    case NONCE_INVALID_ORBIT_FAILURE:
      return SERVER_NONCE_INVALID_FAILURE;
    case NONCE_NOT_UNIQUE_FAILURE:
      return SERVER_NONCE_NOT_UNIQUE_FAILURE;
    case NONCE_INVALID_TIME_FAILURE:
      return SERVER_NONCE_INVALID_TIME_FAILURE;
    case NONCE_UNKNOWN_FAILURE:
    case STRIKE_REGISTER_TIMEOUT:
    case STRIKE_REGISTER_FAILURE:
    default:
      QUIC_BUG << "Unexpected server nonce error: " << nonce_error;
      return SERVER_NONCE_NOT_UNIQUE_FAILURE;
  }
}

bool QuicCryptoServerConfig::ValidateExpectedLeafCertificate(
    const CryptoHandshakeMessage& client_hello,
    const QuicCryptoProof& crypto_proof) const {
  if (crypto_proof.chain->certs.empty()) {
    return false;
  }

  uint64_t hash_from_client;
  if (client_hello.GetUint64(kXLCT, &hash_from_client) != QUIC_NO_ERROR) {
    return false;
  }
  return CryptoUtils::ComputeLeafCertHash(crypto_proof.chain->certs.at(0)) ==
         hash_from_client;
}

void QuicCryptoServerConfig::ParseProofDemand(
    const CryptoHandshakeMessage& client_hello,
    bool* x509_supported,
    bool* x509_ecdsa_supported) const {
  const QuicTag* their_proof_demands;
  size_t num_their_proof_demands;

  if (client_hello.GetTaglist(kPDMD, &their_proof_demands,
                              &num_their_proof_demands) != QUIC_NO_ERROR) {
    return;
  }

  *x509_supported = false;
  for (size_t i = 0; i < num_their_proof_demands; i++) {
    switch (their_proof_demands[i]) {
      case kX509:
        *x509_supported = true;
        *x509_ecdsa_supported = true;
        break;
      case kX59R:
        *x509_supported = true;
        break;
    }
  }
}

QuicCryptoServerConfig::Config::Config()
    : channel_id_enabled(false),
      is_primary(false),
      primary_time(QuicWallTime::Zero()),
      priority(0),
      source_address_token_boxer(nullptr) {}

QuicCryptoServerConfig::Config::~Config() {
  STLDeleteElements(&key_exchanges);
}

QuicCryptoProof::QuicCryptoProof() {}
QuicCryptoProof::~QuicCryptoProof() {}
}  // namespace net
