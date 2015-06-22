// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_handshake.h"

#include "net/quic/crypto/common_cert_set.h"
#include "net/quic/crypto/key_exchange.h"
#include "net/quic/crypto/quic_decrypter.h"
#include "net/quic/crypto/quic_encrypter.h"

namespace net {

QuicCryptoNegotiatedParameters::QuicCryptoNegotiatedParameters()
    : key_exchange(0),
      aead(0),
      x509_ecdsa_supported(false) {
}

QuicCryptoNegotiatedParameters::~QuicCryptoNegotiatedParameters() {}

CrypterPair::CrypterPair() {}

CrypterPair::~CrypterPair() {}

// static
const char QuicCryptoConfig::kInitialLabel[] = "QUIC key expansion";

// static
const char QuicCryptoConfig::kCETVLabel[] = "QUIC CETV block";

// static
const char QuicCryptoConfig::kForwardSecureLabel[] =
    "QUIC forward secure key expansion";

QuicCryptoConfig::QuicCryptoConfig()
    : common_cert_sets(CommonCertSets::GetInstanceQUIC()) {
}

QuicCryptoConfig::~QuicCryptoConfig() {}

}  // namespace net
