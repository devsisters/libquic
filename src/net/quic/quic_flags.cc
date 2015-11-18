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

// Time period for which a given connection_id should live in the time-wait
// state.
int64 FLAGS_quic_time_wait_list_seconds = 200;

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps.  Regardless, this means that
// the longest time-wait list we should see is 200 seconds * 1000 qps = 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
int64 FLAGS_quic_time_wait_list_max_connections = 600000;

// Enables server-side support for QUIC stateless rejects.
bool FLAGS_enable_quic_stateless_reject_support = true;

// If true, flow controller may grow the receive window size if necessary.
bool FLAGS_quic_auto_tune_receive_window = true;

// Limits QUIC's max CWND to 200 packets.
bool FLAGS_quic_limit_max_cwnd = true;

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
bool FLAGS_quic_require_handshake_confirmation = false;

// If true, after a server silo receives a packet from a migrated QUIC
// client, a GO_AWAY frame is sent to the client.
bool FLAGS_send_goaway_after_client_migration = true;

// QUIC-specific flag. If true, Cubic's epoch is reset when the sender is
// application-limited.
bool FLAGS_reset_cubic_epoch_when_app_limited = true;

// If true, use an interval set as the internal representation of a packet queue
// instead of a set.
bool FLAGS_quic_packet_queue_use_interval_set = true;

// If true, Cubic's epoch is shifted when the sender is application-limited.
bool FLAGS_shift_quic_cubic_epoch_when_app_limited = true;

// If true, accounts for available (implicitly opened) streams under a separate
// quota from open streams, which is 10 times larger.
bool FLAGS_allow_many_available_streams = true;

// If true, QuicPacketReader::ReadAndDispatchPackets will only return true if
// recvmmsg fills all of the passed in messages. Otherwise, it will return true
// if recvmmsg read any messages.
bool FLAGS_quic_read_packets_full_recvmmsg = true;

// If true, QUIC will measure head of line (HOL) blocking due between
// streams due to packet losses on the headers stream.  The
// measurements will be surfaced via UMA histogram
// Net.QuicSession.HeadersHOLBlockedTime.
bool FLAGS_quic_measure_headers_hol_blocking_time = true;

// Disable QUIC's userspace pacing.
bool FLAGS_quic_disable_pacing = false;

// If true, a FIN received on a stream with read_side_closed_ true will be
// recorded correctly.
bool FLAGS_quic_fix_fin_accounting = true;

// If true, ReliableQuicStream::StopReading (formerly CloseReadSide) causes
// incoming data to be ignored but the read side of the stream object is not
// closed.
bool FLAGS_quic_implement_stop_reading = true;

// Invoke the QuicAckListener directly, instead of going through the AckNotifier
// and AckNotifierManager.
bool FLAGS_quic_no_ack_notifier = true;

// If true, QuicSession::GetNumOpenStreams will count unfinished
// streams as open streams, QuicSession::PostProcessAfterData will not
// check the quota of unifinished streams.
bool FLAGS_quic_count_unfinished_as_open_streams = true;

// If true, use the unrolled prefetch path in QuicPacketCreator::CopyToBuffer.
bool FLAGS_quic_packet_creator_prefetch = false;

// If true, only migrate QUIC connections when client address changes are
// considered to be caused by NATs.
bool FLAGS_quic_disable_non_nat_address_migration = true;

// If true, QUIC connections will timeout when packets are not being recieved,
// even if they are being sent.
bool FLAGS_quic_use_new_idle_timeout = true;

// If true, replace QuicFrameList with StreamSequencerBuffer as underlying data
// structure for QuicStreamSequencer bufferring.
bool FLAGS_quic_use_stream_sequencer_buffer = true;

// If true, don't send QUIC packets if the send alarm is set.
// Disabled until b/25638635 is resolved.
bool FLAGS_respect_send_alarm = false;
