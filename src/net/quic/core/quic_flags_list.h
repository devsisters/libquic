// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate values.

// This file contains the list of QUIC protocol flags.

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
QUIC_FLAG(bool, FLAGS_quic_allow_bbr, false)

// Time period for which a given connection_id should live in the time-wait
// state.
QUIC_FLAG(int64_t, FLAGS_quic_time_wait_list_seconds, 200)

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps.  Regardless, this means that
// the longest time-wait list we should see is 200 seconds * 1000 qps, 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
QUIC_FLAG(int64_t, FLAGS_quic_time_wait_list_max_connections, 600000)

// Enables server-side support for QUIC stateless rejects.
QUIC_FLAG(bool, FLAGS_enable_quic_stateless_reject_support, true)

// This flag is not in use, just to keep consistency for shared code.
QUIC_FLAG(bool, FLAGS_quic_always_log_bugs_for_tests, true)

// If true, multipath is enabled for the connection.
QUIC_FLAG(bool, FLAGS_quic_enable_multipath, false)

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
QUIC_FLAG(bool, FLAGS_quic_require_handshake_confirmation, false)

// If true, disable pacing in QUIC.
QUIC_FLAG(bool, FLAGS_quic_disable_pacing_for_perf_tests, false)

// If true, QUIC connections can do bandwidth resumption with an initial window
// of < 10 packets.
QUIC_FLAG(bool, FLAGS_quic_no_lower_bw_resumption_limit, true)

// If true, QUIC public reset packets will have the \"pre-v33\" public header
// flags.
QUIC_FLAG(bool, FLAGS_quic_use_old_public_reset_packets, true)

// If true, QUIC will use cheap stateless rejects without creating a full
// connection.
QUIC_FLAG(bool, FLAGS_quic_use_cheap_stateless_rejects, false)

// If true, QUIC respect HTTP2 SETTINGS frame rather than always close the
// connection.
QUIC_FLAG(bool, FLAGS_quic_respect_http2_settings_frame, true)

// If true, enables QUIC_VERSION_35.
QUIC_FLAG(bool, FLAGS_quic_enable_version_35, true)

// If true, re-enables QUIC_VERSION_36.
QUIC_FLAG(bool, FLAGS_quic_enable_version_36_v2, true)

// If true, use async codepaths to invoke ProofSource::GetProof.
QUIC_FLAG(bool, FLAGS_enable_async_get_proof, false)

// If true, requires handshake confirmations for all QUIC handshakes with
// versions less than 33.
QUIC_FLAG(bool, FLAGS_quic_require_handshake_confirmation_pre33, false)

// If true, close QUIC connection explicitly on write error due to packet being
// too large.
QUIC_FLAG(bool, FLAGS_quic_close_connection_on_packet_too_large, true)

// If true, v33 QUIC client uses 1 bit to specify 8-byte connection id in public
// flag.
QUIC_FLAG(bool, FLAGS_quic_remove_v33_hacks, true)

// If true, use the CHLO packet size, not message size when determining how
// large a REJ can be.
QUIC_FLAG(bool, FLAGS_quic_use_chlo_packet_size, true)

// If true, defer creation of new connection till its CHLO arrives.
QUIC_FLAG(bool, FLAGS_quic_buffer_packet_till_chlo, true)

// Deprecate QuicPacketCreator::next_packet_number_length_ because it's no
// longer necessary.
QUIC_FLAG(bool, FLAGS_quic_simple_packet_number_length_2, true)

// If true, disables QUIC version less than 32.
QUIC_FLAG(bool, FLAGS_quic_disable_pre_32, true)

// If true, QUIC will enforce the MTU limit for connections that may require a
// small MTU.
QUIC_FLAG(bool, FLAGS_quic_enforce_mtu_limit, false)

// Disable MTU probing if MTU probe causes ERR_MSG_TOO_BIG instead of aborting
// the connection.
QUIC_FLAG(bool, FLAGS_graceful_emsgsize_on_mtu_probe, true)

// If true, do not force sending ack when connection is closed because of
// message too long (EMSGSIZE) write error.
QUIC_FLAG(bool, FLAGS_quic_do_not_send_ack_on_emsgsize, true)

// If true, postpone multipath flag validation to ProcessValidatedPacket.
QUIC_FLAG(bool, FLAGS_quic_postpone_multipath_flag_validation, true)

// If true, set a QUIC connection's last_sent_for_timeout_ to the send time of
// the first packet sent after receiving a packet, even if the sent packet is
// a retransmission
QUIC_FLAG(bool, FLAGS_quic_better_last_send_for_timeout, true)

// If true, send an explicit TTL in QUIC REJ messages to mitigate client clock
// skew.
QUIC_FLAG(bool, FLAGS_quic_send_scfg_ttl, true)

// If true, only open limited number of quic sessions per epoll event. Leave the
// rest to next event. This flag can be turned on only if
// --quic_buffer_packet_till_chlo is true.
QUIC_FLAG(bool, FLAGS_quic_limit_num_new_sessions_per_epoll_loop, false)

// If true, lazy allocate and early release memeory used in
// QuicStreamSequencerBuffer to buffer incoming data.
QUIC_FLAG(bool, FLAGS_quic_reduce_sequencer_buffer_memory_life_time, true)

// If true, allow server address change if it is because of mapped ipv4 address.
QUIC_FLAG(bool, FLAGS_quic_allow_server_address_change_for_mapped_ipv4, true)

// If true, disables QUIC version less than 34.
QUIC_FLAG(bool, FLAGS_quic_disable_pre_34, false)

// When true, decode the packet number from the largest received packet, rather
// than the most recent.
QUIC_FLAG(bool, FLAGS_quic_packet_numbers_largest_received, true)
