// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_flags.h"

bool FLAGS_quic_allow_oversized_packets_for_test = false;

// When true, the use time based loss detection instead of nack.
bool FLAGS_quic_use_time_loss_detection = false;

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

// If true, QUIC connections will support FEC protection of data while sending
// packets, to reduce latency of data delivery to the application. The client
// must also request FEC protection for the server to use FEC.
bool FLAGS_enable_quic_fec = false;

// When true, defaults to BBR congestion control instead of Cubic.
bool FLAGS_quic_use_bbr_congestion_control = false;

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
bool FLAGS_quic_allow_bbr = false;

// Do not flip this flag.  jokulik plans more testing and additional monitoring
// before the flag can go the auto-flip process.
//
// If true, record the timestamp for the last sent new packet before the call to
// WritePacket, rather than after in QUIC.
bool FLAGS_quic_record_send_time_before_write = false;

// If true, enables the QUIC bandwidth resumption experiment (triggered by
// Chrome/Finch).
bool FLAGS_quic_enable_bandwidth_resumption_experiment = true;

// If true, QUIC congestion control will be paced.  If false, pacing may be
// controlled by QUIC connection options in the config or by enabling BBR
// congestion control.
bool FLAGS_quic_enable_pacing = false;

// If true, use std::cbrt instead of custom cube root.
bool FLAGS_quic_use_std_cbrt = true;

// If true, then the source address tokens generated for QUIC connects will
// store multiple addresses.
bool FLAGS_quic_use_multiple_address_in_source_tokens = false;

// If true, uses the last sent packet for the RTO timer instead of the earliest.
bool FLAGS_quic_rto_uses_last_sent = true;

// If true, attach QuicAckNotifiers to packets rather than individual stream
// frames.
bool FLAGS_quic_attach_ack_notifiers_to_packets = true;

// If true, the AckNotifierManager is informed about new packets as soon as they
// are serialized.
bool FLAGS_quic_ack_notifier_informed_on_serialized = true;

// If true, QUIC will use the new RTO that waits until an ack arrives to adjust
// the congestion window.
bool FLAGS_quic_use_new_rto = true;

// Time period for which a given connection_id should live in the time-wait
// state.
int64 FLAGS_quic_time_wait_list_seconds = 5;

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps. Regardless, this means that the
// longest time-wait list we should see is 5 seconds * 1000 qps = 5000.  If we
// allow for an order of magnitude leeway, we have 50000.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
int64 FLAGS_quic_time_wait_list_max_connections = 50000;

// If true, limit the number of connections on the quic time-wait list using a
// flag.
bool FLAGS_quic_limit_time_wait_list_size = true;
