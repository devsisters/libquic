// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_flags.h"

// When true, the use time based loss detection instead of nack.
bool FLAGS_quic_use_time_loss_detection = false;

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

// If true, QUIC connections will support FEC protection of data while sending
// packets, to reduce latency of data delivery to the application. The client
// must also request FEC protection for the server to use FEC.
bool FLAGS_enable_quic_fec = true;

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
bool FLAGS_quic_always_log_bugs_for_tests = false;

// If true, flow controller may grow the receive window size if necessary.
bool FLAGS_quic_auto_tune_receive_window = true;

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

// If true, QUIC connections will timeout when packets are not being recieved,
// even if they are being sent.
bool FLAGS_quic_use_new_idle_timeout = true;

// If true, replace QuicFrameList with StreamSequencerBuffer as underlying data
// structure for QuicStreamSequencer bufferring.
bool FLAGS_quic_use_stream_sequencer_buffer = true;

// If true, don't send QUIC packets if the send alarm is set.
bool FLAGS_quic_respect_send_alarm2 = true;

// If true, allow each quic stream to write 16k blocks rather than doing a round
// robin of one packet per session when ack clocked or paced.
bool FLAGS_quic_batch_writes = true;

// If true, QUIC sessions will write block streams that attempt to write
// unencrypted data.
bool FLAGS_quic_block_unencrypted_writes = true;

// If true, Close the connection instead of writing unencrypted stream data.
bool FLAGS_quic_never_write_unencrypted_data = true;

// If true, clear the FEC group instead of sending it with ENCRYPTION_NONE.
// Close the connection if we ever try to serialized unencrypted FEC.
bool FLAGS_quic_no_unencrypted_fec = true;

// If true, reject any incoming QUIC which does not have the FIXD tag.
bool FLAGS_quic_require_fix = true;

// If true, QUIC supports sending trailers from Server to Client.
bool FLAGS_quic_supports_trailers = true;

// If true, headers stream will support receiving PUSH_PROMISE frames.
bool FLAGS_quic_supports_push_promise = false;

// Enable counters for incoming/outgoing streams which are used as condition
// check while creating a new stream.
bool FLAGS_quic_distinguish_incoming_outgoing_streams = true;

// If true, QUIC servers will attempt to validate a client's source
// address token using the primary config, even if no server config id
// is present in the client hello.
bool FLAGS_quic_validate_stk_without_scid = true;

// If true, QUIC will support RFC 7539 variants of ChaCha20 Poly1305.
bool FLAGS_quic_use_rfc7539 = true;

// If true, require QUIC connections to use a valid server nonce or a non-local
// strike register.
bool FLAGS_require_strike_register_or_server_nonce = true;

// When turn on, log packet loss into transport connection stats LossEvent.
bool FLAGS_quic_log_loss_event = true;

// If true, for QUIC authenticated encryption algorithms, last 8 bytes
// of IV comprise packet path id and lower 7 bytes of packet number.
bool FLAGS_quic_include_path_id_in_iv = true;

// If true, make sure new incoming streams correctly cede to higher
// priority (or batch) streams when doing QUIC writes.
bool FLAGS_quic_cede_correctly = true;

// If on, max number of incoming and outgoing streams will be different.
// Incoming will be a little higher than outgoing to tolerate race condition.
bool FLAGS_quic_different_max_num_open_streams = true;

// If true, QUIC should correctly report if it supports ChaCha20. Otherwise,
// QUIC will lie and claim that it does not support ChaCha20. The primary use
// case for this is places where ChaCha20 is prohibitively expensive compared to
// AES-GCM.
bool FLAGS_quic_crypto_server_config_default_has_chacha20 = true;

// If true, checking for peer address change is postponed after the packet gets
// decrypted.
bool FLAGS_check_peer_address_change_after_decryption = true;

// If true, always log the cached network parameters, regardless of whether
// bandwidth-resumption has been enabled.
bool FLAGS_quic_log_received_parameters = true;

// If true, QUIC will use newly refactored TCP sender code.
bool FLAGS_quic_use_new_tcp_sender = true;

// Saves the initial subkey secret in QUIC crypto when deriving keys from the
// initial premaster secret.
bool FLAGS_quic_save_initial_subkey_secret = true;
