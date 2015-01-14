// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CACHED_NETWORK_PARAMETERS_H_
#define NET_QUIC_CRYPTO_CACHED_NETWORK_PARAMETERS_H_

#include <string>

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

// TODO(rtenneti): sync with server more rationally.
// CachedNetworkParameters contains data that can be used to choose appropriate
// connection parameters (initial RTT, initial CWND, etc.) in new connections.
class NET_EXPORT_PRIVATE CachedNetworkParameters {
 public:
  // Describes the state of the connection during which the supplied network
  // parameters were calculated.
  enum PreviousConnectionState {
    SLOW_START = 0,
    CONGESTION_AVOIDANCE = 1,
  };

  CachedNetworkParameters();
  ~CachedNetworkParameters();

  bool operator==(const CachedNetworkParameters& other) const;
  bool operator!=(const CachedNetworkParameters& other) const;

  std::string serving_region() const {
    return serving_region_;
  }
  void set_serving_region(base::StringPiece serving_region) {
    serving_region_ = serving_region.as_string();
  }

  int32 bandwidth_estimate_bytes_per_second() const {
    return bandwidth_estimate_bytes_per_second_;
  }
  void set_bandwidth_estimate_bytes_per_second(
      int32 bandwidth_estimate_bytes_per_second) {
    bandwidth_estimate_bytes_per_second_ = bandwidth_estimate_bytes_per_second;
  }

  int32 max_bandwidth_estimate_bytes_per_second() const {
    return max_bandwidth_estimate_bytes_per_second_;
  }
  void set_max_bandwidth_estimate_bytes_per_second(
      int32 max_bandwidth_estimate_bytes_per_second) {
    max_bandwidth_estimate_bytes_per_second_ =
        max_bandwidth_estimate_bytes_per_second;
  }

  int64 max_bandwidth_timestamp_seconds() const {
    return max_bandwidth_timestamp_seconds_;
  }
  void set_max_bandwidth_timestamp_seconds(
      int64 max_bandwidth_timestamp_seconds) {
    max_bandwidth_timestamp_seconds_ = max_bandwidth_timestamp_seconds;
  }

  int32 min_rtt_ms() const {
    return min_rtt_ms_;
  }
  void set_min_rtt_ms(int32 min_rtt_ms) {
    min_rtt_ms_ = min_rtt_ms;
    has_min_rtt_ms_ = true;
  }
  bool has_min_rtt_ms() const { return has_min_rtt_ms_; }

  int32 previous_connection_state() const {
    return previous_connection_state_;
  }
  void set_previous_connection_state(int32 previous_connection_state) {
    previous_connection_state_ = previous_connection_state;
  }

  int64 timestamp() const { return timestamp_; }
  void set_timestamp(int64 timestamp) { timestamp_ = timestamp; }

 private:
  // serving_region_ is used to decide whether or not the bandwidth estimate and
  // min RTT are reasonable and if they should be used.
  // For example a group of geographically close servers may share the same
  // serving_region_ string if they are expected to have similar network
  // performance.
  std::string serving_region_;
  // The server can supply a bandwidth estimate (in bytes/s) which it may re-use
  // on receipt of a source-address token with this field set.
  int32 bandwidth_estimate_bytes_per_second_;
  // The maximum bandwidth seen by the client, not necessarily the latest.
  int32 max_bandwidth_estimate_bytes_per_second_;
  // Timestamp (seconds since UNIX epoch) that indicates when the max bandwidth
  // was seen by the server.
  int64 max_bandwidth_timestamp_seconds_;
  // The min RTT seen on a previous connection can be used by the server to
  // inform initial connection parameters for new connections.
  int32 min_rtt_ms_;
  // Whenever min_rtt_ms_ is updated, it is set to true.
  bool has_min_rtt_ms_;
  // Encodes the PreviousConnectionState enum.
  int32 previous_connection_state_;
  // UNIX timestamp when this bandwidth estimate was created.
  int64 timestamp_;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CACHED_NETWORK_PARAMETERS_H_
