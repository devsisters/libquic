// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_flags.h"

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

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

// If true, disable pacing in QUIC.
bool FLAGS_quic_disable_pacing_for_perf_tests = false;

// If true, Close the connection instead of writing unencrypted stream data.
bool FLAGS_quic_never_write_unencrypted_data = true;

// If true, headers stream will support receiving PUSH_PROMISE frames.
bool FLAGS_quic_supports_push_promise = true;

// If true, QUIC connections can do bandwidth resumption with an initial window
// of < 10 packets.
bool FLAGS_quic_no_lower_bw_resumption_limit = true;

// If true, flow controller may grow the receive window size if necessary.
bool FLAGS_quic_auto_tune_receive_window = true;

// If true, enable auto tuning by default (server side).
bool FLAGS_quic_enable_autotune_by_default = true;

// Use largest acked in the most recent ack instead of largest acked ever in
// loss recovery.
bool FLAGS_quic_loss_recovery_use_largest_acked = true;

// Only set one alarm for sending at once, either the send alarm or
// retransmission alarm.  Disabled because it breaks QUIC time loss detection.
bool FLAGS_quic_only_one_sending_alarm = false;

// If true, the hash of the CHLO message will be used in the proof generated for
// an SCUP message.
bool FLAGS_quic_use_hash_in_scup = true;

// If true, QUIC public reset packets will have the \"pre-v33\" public header
// flags.
bool FLAGS_quic_use_old_public_reset_packets = true;

// If true, the dispatcher is responsible for generating server designated
// connection IDs.
bool FLAGS_quic_dispatcher_creates_id = true;

// If true, checks if the CHLO is acceptable as a matter of policy.
bool FLAGS_quic_enable_chlo_policy = true;

// If true, ignore QUIC data frames of length 0 for flow control.
bool FLAGS_quic_ignore_zero_length_frames = true;

// If true, replace ServerHelloNotifier with a check to see if a decrypted
// packet is forward secure.
bool FLAGS_quic_no_shlo_listener = true;

// If true, queued retransmission packets, because of write blocked
// socket, are always sent once the socket gets unblocked
bool FLAGS_quic_always_write_queued_retransmissions = true;

// Adds a RATE connection option to do rate based sending.
bool FLAGS_quic_rate_based_sending = true;

// If true, QUIC will use cheap stateless rejects without creating a full
// connection.
bool FLAGS_quic_use_cheap_stateless_rejects = false;

// If true, treat timestamps from SO_TIMESTAMPING as QuicWallTimes rather
// than QuicTimes.
bool FLAGS_quic_socket_walltimestamps = false;

// If true, default to immediate forward secure once established on the
// server side, and the IPFS connection option disables this instead of
// enabling it.
bool FLAGS_quic_default_immediate_forward_secure = true;

// If true, disables support for QUIC version 29 and earlier.
bool FLAGS_quic_disable_pre_30 = false;

// If true, QUIC respect HTTP2 SETTINGS frame rather than always close the
// connection.
bool FLAGS_quic_respect_http2_settings_frame = true;

// Do not use a QuicAckListener in order to confirm a larger Path MTU.
bool FLAGS_quic_no_mtu_discovery_ack_listener = false;

// Deprecate QuicPacketCreator::next_packet_number_length_ because it's no
// longer necessary.
bool FLAGS_quic_simple_packet_number_length = false;

// If true, enables QUIC_VERSION_35.
bool FLAGS_quic_enable_version_35 = false;

// If true, enables QUIC_VERSION_36.
bool FLAGS_quic_enable_version_36 = false;

// If true, requires support for X509 certificates in QUIC CHLO PDMDs.
bool FLAGS_quic_require_x509 = false;

// If true, deprecate safeguards for b/26023400.
bool FLAGS_quic_deprecate_kfixd = false;

// If true, QUIC will refresh the proof for versions 31 and beyond on subsequent
// CHLOs.
bool FLAGS_quic_refresh_proof = true;

// If true, a connection does not migrate on an old packet even the peer address
// changes.
bool FLAGS_quic_do_not_migrate_on_old_packet = true;

// If true, use async codepaths to invoke ProofSource::GetProof.
bool FLAGS_enable_async_get_proof = false;

// If true, neuter null encrypted packets before sending the next handshake
// message.
bool FLAGS_quic_neuter_unencrypted_when_sending = false;
