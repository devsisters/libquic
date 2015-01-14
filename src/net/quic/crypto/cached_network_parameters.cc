// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/cached_network_parameters.h"

namespace net {

CachedNetworkParameters::CachedNetworkParameters()
    : bandwidth_estimate_bytes_per_second_(0),
      max_bandwidth_estimate_bytes_per_second_(0),
      max_bandwidth_timestamp_seconds_(0),
      min_rtt_ms_(0),
      has_min_rtt_ms_(false),
      previous_connection_state_(0),
      timestamp_(0) {
}

CachedNetworkParameters::~CachedNetworkParameters() {
}

bool CachedNetworkParameters::operator==(
    const CachedNetworkParameters& other) const {
  return serving_region_ == other.serving_region_ &&
      bandwidth_estimate_bytes_per_second_ ==
          other.bandwidth_estimate_bytes_per_second_ &&
      max_bandwidth_estimate_bytes_per_second_ ==
          other.max_bandwidth_estimate_bytes_per_second_ &&
      max_bandwidth_timestamp_seconds_ ==
          other.max_bandwidth_timestamp_seconds_ &&
      min_rtt_ms_ == other.min_rtt_ms_ &&
      previous_connection_state_ == other.previous_connection_state_ &&
      timestamp_ == other.timestamp_;
}

bool CachedNetworkParameters::operator!=(
    const CachedNetworkParameters& other) const {
  return !(*this == other);
}

}  // namespace net
