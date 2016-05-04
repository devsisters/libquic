// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_flags.h"

// When true, the use time based loss detection instead of nack.
bool FLAGS_quic_use_time_loss_detection = false;

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

// When true, defaults to BBR congestion control instead of Cubic.
bool FLAGS_quic_use_bbr_congestion_control = false;

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
bool FLAGS_quic_allow_bbr = false;

// Time period for which a given connection_id should live in the time-wait
// state.
int64_t FLAGS_quic_time_wait_list_seconds = 200;

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps.  Regardless, this means that
// the longest time-wait list we should see is 200 seconds * 1000 qps = 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
int64_t FLAGS_quic_time_wait_list_max_connections = 600000;

// Enables server-side support for QUIC stateless rejects.
bool FLAGS_enable_quic_stateless_reject_support = true;

// This flag is not in use, just to keep consistency for shared code.
bool FLAGS_quic_always_log_bugs_for_tests = true;

// If true, a QUIC connection option with tag DHDT can be used to disable
// HPACK\'s dynamic table.
bool FLAGS_quic_disable_hpack_dynamic_table = true;

// If true, multipath is enabled for the connection.
bool FLAGS_quic_enable_multipath = false;

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
bool FLAGS_quic_require_handshake_confirmation = false;

// If true, Cubic's epoch is shifted when the sender is application-limited.
bool FLAGS_shift_quic_cubic_epoch_when_app_limited = true;

// If true, QUIC will measure head of line (HOL) blocking due between
// streams due to packet losses on the headers stream.  The
// measurements will be surfaced via UMA histogram
// Net.QuicSession.HeadersHOLBlockedTime.
bool FLAGS_quic_measure_headers_hol_blocking_time = true;

// Disable QUIC's userspace pacing.
bool FLAGS_quic_disable_pacing = false;

// If true, Close the connection instead of writing unencrypted stream data.
bool FLAGS_quic_never_write_unencrypted_data = true;

// If true, reject any incoming QUIC which does not have the FIXD tag.
bool FLAGS_quic_require_fix = true;

// If true, headers stream will support receiving PUSH_PROMISE frames.
bool FLAGS_quic_supports_push_promise = true;

// If true, make sure new incoming streams correctly cede to higher
// priority (or batch) streams when doing QUIC writes.
bool FLAGS_quic_cede_correctly = true;

// If true, QUIC should correctly report if it supports ChaCha20. Otherwise,
// QUIC will lie and claim that it does not support ChaCha20. The primary use
// case for this is places where ChaCha20 is prohibitively expensive compared to
// AES-GCM.
bool FLAGS_quic_crypto_server_config_default_has_chacha20 = true;

// If true, QUIC will use newly refactored TCP sender code.
bool FLAGS_quic_use_new_tcp_sender = true;

// If true, the QUIC dispatcher will directly send version negotiation packets
// without needing to create a QUIC session first.
bool FLAGS_quic_stateless_version_negotiation = true;

// If true, QUIC connections will defer responding to ACKs to their send alarms.
bool FLAGS_quic_connection_defer_ack_response = true;

// Enable a connection option allowing connections to time out if more than 5
// consecutive RTOs are sent.
bool FLAGS_quic_enable_rto_timeout = true;

// Try to use the socket timestamp to determine the time a packet was
// received instead of Now().
bool FLAGS_quic_use_socket_timestamp = true;

// Resend 0RTT requests in response to an REJ that re-establishes encryption.
bool FLAGS_quic_reply_to_rej = true;

// If true, QuicFramer will ignore invalid error codes when processing GoAway,
// ConnectionClose, and RstStream frames.
bool FLAGS_quic_ignore_invalid_error_code = true;

// If true, QUIC connections can do bandwidth resumption with an initial window
// of < 10 packets.
bool FLAGS_quic_no_lower_bw_resumption_limit = true;

// Limit the ruction of slow start large reduction to 1/2 the current CWND once
// the initial flight has been acked.
bool FLAGS_quic_sslr_limit_reduction = true;

// Simplify QUIC's loss detection by combining time and nack based portions.
bool FLAGS_quic_simplify_loss_detection = true;

// If true, do not check HasUnackedPackets on retransmission timeout.
bool FLAGS_quic_always_has_unacked_packets_on_timeout = true;
