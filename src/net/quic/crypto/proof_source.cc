// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/proof_source.h"

namespace net {

ProofSource::Chain::Chain(const std::vector<std::string>& certs)
    : certs(certs) {}

ProofSource::Chain::~Chain() {}

}  // namespace net
