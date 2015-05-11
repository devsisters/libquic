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
NET_EXPORT_PRIVATE extern int64 FLAGS_quic_time_wait_list_seconds;
NET_EXPORT_PRIVATE extern int64 FLAGS_quic_time_wait_list_max_connections;
NET_EXPORT_PRIVATE extern bool FLAGS_quic_limit_max_cwnd_to_receive_buffer;
NET_EXPORT_PRIVATE extern bool FLAGS_enable_quic_stateless_reject_support;

#endif  // NET_QUIC_QUIC_FLAGS_H_
