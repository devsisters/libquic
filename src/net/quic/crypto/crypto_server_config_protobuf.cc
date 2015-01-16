// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/crypto_server_config_protobuf.h"

#include "base/stl_util.h"
#include "net/quic/quic_time.h"

namespace net {

QuicServerConfigProtobuf::QuicServerConfigProtobuf()
    : primary_time_(QuicWallTime::Zero().ToUNIXSeconds()),
      priority_(0) {
}

QuicServerConfigProtobuf::~QuicServerConfigProtobuf() {
  STLDeleteElements(&keys_);
}

}  // namespace net
