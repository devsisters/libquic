// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/channel_id.h"

namespace net {

// static
const char ChannelIDVerifier::kContextStr[] = "QUIC ChannelID";
// static
const char ChannelIDVerifier::kClientToServerStr[] = "client -> server";

}  // namespace net
