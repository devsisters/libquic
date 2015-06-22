// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_utils.h"

#include "crypto/hkdf.h"
#include "net/base/net_util.h"
#include "net/quic/crypto/crypto_handshake.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"
#include "net/quic/crypto/quic_random.h"
#include "net/quic/quic_time.h"
#if 0
#include "url/url_canon.h"
#endif

using base::StringPiece;
using std::numeric_limits;
using std::string;

namespace net {

// static
void CryptoUtils::GenerateNonce(QuicWallTime now,
                                QuicRandom* random_generator,
                                StringPiece orbit,
                                string* nonce) {
  // a 4-byte timestamp + 28 random bytes.
  nonce->reserve(kNonceSize);
  nonce->resize(kNonceSize);

  uint32 gmt_unix_time = static_cast<uint32>(now.ToUNIXSeconds());
  // The time in the nonce must be encoded in big-endian because the
  // strike-register depends on the nonces being ordered by time.
  (*nonce)[0] = static_cast<char>(gmt_unix_time >> 24);
  (*nonce)[1] = static_cast<char>(gmt_unix_time >> 16);
  (*nonce)[2] = static_cast<char>(gmt_unix_time >> 8);
  (*nonce)[3] = static_cast<char>(gmt_unix_time);
  size_t bytes_written = 4;

  if (orbit.size() == 8) {
    memcpy(&(*nonce)[bytes_written], orbit.data(), orbit.size());
    bytes_written += orbit.size();
  }

  random_generator->RandBytes(&(*nonce)[bytes_written],
                              kNonceSize - bytes_written);
}

#if 0
// static
bool CryptoUtils::IsValidSNI(StringPiece sni) {
  // TODO(rtenneti): Support RFC2396 hostname.
  // NOTE: Microsoft does NOT enforce this spec, so if we throw away hostnames
  // based on the above spec, we may be losing some hostnames that windows
  // would consider valid. By far the most common hostname character NOT
  // accepted by the above spec is '_'.
  url::CanonHostInfo host_info;
  string canonicalized_host(CanonicalizeHost(sni.as_string(), &host_info));
  return !host_info.IsIPAddress() &&
      IsCanonicalizedHostCompliant(canonicalized_host) &&
      sni.find_last_of('.') != string::npos;
}

// static
string CryptoUtils::NormalizeHostname(const char* hostname) {
  url::CanonHostInfo host_info;
  string host(CanonicalizeHost(hostname, &host_info));

  // Walk backwards over the string, stopping at the first trailing dot.
  size_t host_end = host.length();
  while (host_end != 0 && host[host_end - 1] == '.') {
    host_end--;
  }

  // Erase the trailing dots.
  if (host_end != host.length()) {
    host.erase(host_end, host.length() - host_end);
  }
  return host;
}
#else
// TODO(hodduc): We should implement this !
// static
bool CryptoUtils::IsValidSNI(StringPiece sni) {
  return sni.find_last_of('.') != string::npos;
}

string CryptoUtils::NormalizeHostname(const char* hostname) {
  string host(hostname);

  // Walk backwards over the string, stopping at the first trailing dot.
  size_t host_end = host.length();
  while (host_end != 0 && host[host_end - 1] == '.') {
    host_end--;
  }

  // Erase the trailing dots.
  if (host_end != host.length()) {
    host.erase(host_end, host.length() - host_end);
  }
  return host;
}
#endif

// static
bool CryptoUtils::DeriveKeys(StringPiece premaster_secret,
                             QuicTag aead,
                             StringPiece client_nonce,
                             StringPiece server_nonce,
                             const string& hkdf_input,
                             Perspective perspective,
                             CrypterPair* crypters,
                             string* subkey_secret) {
  crypters->encrypter.reset(QuicEncrypter::Create(aead));
  crypters->decrypter.reset(QuicDecrypter::Create(aead));
  size_t key_bytes = crypters->encrypter->GetKeySize();
  size_t nonce_prefix_bytes = crypters->encrypter->GetNoncePrefixSize();
  size_t subkey_secret_bytes =
      subkey_secret == nullptr ? 0 : premaster_secret.length();

  StringPiece nonce = client_nonce;
  string nonce_storage;
  if (!server_nonce.empty()) {
    nonce_storage = client_nonce.as_string() + server_nonce.as_string();
    nonce = nonce_storage;
  }

  crypto::HKDF hkdf(premaster_secret, nonce, hkdf_input, key_bytes,
                    nonce_prefix_bytes, subkey_secret_bytes);
  if (perspective == Perspective::IS_SERVER) {
    if (!crypters->encrypter->SetKey(hkdf.server_write_key()) ||
        !crypters->encrypter->SetNoncePrefix(hkdf.server_write_iv()) ||
        !crypters->decrypter->SetKey(hkdf.client_write_key()) ||
        !crypters->decrypter->SetNoncePrefix(hkdf.client_write_iv())) {
      return false;
    }
  } else {
    if (!crypters->encrypter->SetKey(hkdf.client_write_key()) ||
        !crypters->encrypter->SetNoncePrefix(hkdf.client_write_iv()) ||
        !crypters->decrypter->SetKey(hkdf.server_write_key()) ||
        !crypters->decrypter->SetNoncePrefix(hkdf.server_write_iv())) {
      return false;
    }
  }
  if (subkey_secret != nullptr) {
    hkdf.subkey_secret().CopyToString(subkey_secret);
  }

  return true;
}

// static
bool CryptoUtils::ExportKeyingMaterial(StringPiece subkey_secret,
                                       StringPiece label,
                                       StringPiece context,
                                       size_t result_len,
                                       string* result) {
  for (size_t i = 0; i < label.length(); i++) {
    if (label[i] == '\0') {
      LOG(ERROR) << "ExportKeyingMaterial label may not contain NULs";
      return false;
    }
  }
  // Create HKDF info input: null-terminated label + length-prefixed context
  if (context.length() >= numeric_limits<uint32>::max()) {
    LOG(ERROR) << "Context value longer than 2^32";
    return false;
  }
  uint32 context_length = static_cast<uint32>(context.length());
  string info = label.as_string();
  info.push_back('\0');
  info.append(reinterpret_cast<char*>(&context_length), sizeof(context_length));
  info.append(context.data(), context.length());

  crypto::HKDF hkdf(subkey_secret,
                    StringPiece() /* no salt */,
                    info,
                    result_len,
                    0 /* no fixed IV */,
                    0 /* no subkey secret */);
  hkdf.client_write_key().CopyToString(result);
  return true;
}

}  // namespace net
