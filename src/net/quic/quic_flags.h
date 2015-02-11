// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FLAGS_H_
#define NET_QUIC_QUIC_FLAGS_H_

#include "base/basictypes.h"
#include "net/base/net_export.h"

NET_EXPORT_PRIVATE extern bool FLAGS_quic_allow_oversized_packets_for_test;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_time_loss_detection;
NET_EXPORT_PRIVATE extern bool FLAGS_use_early_return_when_verifying_chlo;
NET_EXPORT_PRIVATE extern bool FLAGS_enable_quic_fec;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_bbr_congestion_control;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_allow_bbr;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_too_many_outstanding_packets;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_record_send_time_before_write;
NET_EXPORT_PRIVATE
extern bool FLAGS_quic_enable_bandwidth_resumption_experiment;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_enable_pacing;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_std_cbrt;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_multiple_address_in_source_tokens;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_rto_uses_last_sent;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_attach_ack_notifiers_to_packets;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_ack_notifier_informed_on_serialized;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_use_new_rto;
NET_EXPORT_PRIVATE extern int64 FLAGS_quic_time_wait_list_seconds;
NET_EXPORT_PRIVATE extern int64 FLAGS_quic_time_wait_list_max_connections;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_limit_time_wait_list_size;

#endif  // NET_QUIC_QUIC_FLAGS_H_
