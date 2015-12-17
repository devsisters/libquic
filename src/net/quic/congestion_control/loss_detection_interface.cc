// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/loss_detection_interface.h"

#include "net/quic/congestion_control/general_loss_algorithm.h"
#include "net/quic/congestion_control/tcp_loss_algorithm.h"
#include "net/quic/congestion_control/time_loss_algorithm.h"
#include "net/quic/quic_flags.h"

namespace net {

// Factory for loss detection algorithm.
LossDetectionInterface* LossDetectionInterface::Create(
    LossDetectionType loss_type) {
  if (FLAGS_quic_general_loss_algorithm) {
    return new GeneralLossAlgorithm(loss_type);
  }
  switch (loss_type) {
    case kNack:
      return new TCPLossAlgorithm();
    case kTime:
      return new TimeLossAlgorithm();
  }
  LOG(DFATAL) << "Unknown loss detection algorithm:" << loss_type;
  return nullptr;
}

}  // namespace net
