// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/basictypes.h"
#include "net/quic/congestion_control/tcp_receiver.h"

namespace net {

// Originally 64K bytes, but increased it to 256K to support higher bitrates.
// static
const QuicByteCount TcpReceiver::kReceiveWindowTCP = 256000;

TcpReceiver::TcpReceiver()
    : receive_window_(kReceiveWindowTCP) {
}

bool TcpReceiver::GenerateCongestionFeedback(
    QuicCongestionFeedbackFrame* feedback) {
  feedback->type = kTCP;
  feedback->tcp.receive_window = receive_window_;
  return true;
}

void TcpReceiver::RecordIncomingPacket(QuicByteCount bytes,
                                       QuicPacketSequenceNumber sequence_number,
                                       QuicTime timestamp) {
}

}  // namespace net
