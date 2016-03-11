// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_server_id.h"

#include <tuple>

#include "base/logging.h"
#include "net/base/host_port_pair.h"
#include "net/base/port_util.h"
#include "url/gurl.h"

using std::string;

namespace net {

QuicServerId::QuicServerId() : privacy_mode_(PRIVACY_MODE_DISABLED) {}

QuicServerId::QuicServerId(const HostPortPair& host_port_pair,
                           PrivacyMode privacy_mode)
    : host_port_pair_(host_port_pair), privacy_mode_(privacy_mode) {}

QuicServerId::QuicServerId(const string& host, uint16_t port)
    : host_port_pair_(host, port), privacy_mode_(PRIVACY_MODE_DISABLED) {}

QuicServerId::QuicServerId(const string& host,
                           uint16_t port,
                           PrivacyMode privacy_mode)
    : host_port_pair_(host, port), privacy_mode_(privacy_mode) {}

QuicServerId::~QuicServerId() {}

bool QuicServerId::operator<(const QuicServerId& other) const {
  return std::tie(host_port_pair_, privacy_mode_) <
         std::tie(other.host_port_pair_, other.privacy_mode_);
}

bool QuicServerId::operator==(const QuicServerId& other) const {
  return privacy_mode_ == other.privacy_mode_ &&
         host_port_pair_.Equals(other.host_port_pair_);
}

// static
QuicServerId QuicServerId::FromString(const std::string& str) {
  GURL url(str);
  if (!url.is_valid())
    return QuicServerId();
  return QuicServerId(HostPortPair::FromURL(url), url.path() == "/private"
                                                      ? PRIVACY_MODE_ENABLED
                                                      : PRIVACY_MODE_DISABLED);
}

string QuicServerId::ToString() const {
  return "https://" + host_port_pair_.ToString() +
         (privacy_mode_ == PRIVACY_MODE_ENABLED ? "/private" : "");
}

}  // namespace net
