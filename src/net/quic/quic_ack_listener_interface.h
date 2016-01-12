// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_ACK_LISTENER_INTERFACE_H_
#define NET_QUIC_QUIC_ACK_LISTENER_INTERFACE_H_

#include "base/memory/ref_counted.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

// Pure virtual class to listen for packet acknowledgements.
class NET_EXPORT_PRIVATE QuicAckListenerInterface
    : public base::RefCounted<QuicAckListenerInterface> {
 public:
  QuicAckListenerInterface() {}

  // Called when a packet is acked.  Called once per packet.
  // |acked_bytes| is the number of data bytes acked.
  virtual void OnPacketAcked(int acked_bytes,
                             QuicTime::Delta delta_largest_observed) = 0;

  // Called when a packet is retransmitted.  Called once per packet.
  // |retransmitted_bytes| is the number of data bytes retransmitted.
  virtual void OnPacketRetransmitted(int retransmitted_bytes) = 0;

 protected:
  friend class base::RefCounted<QuicAckListenerInterface>;

  // Delegates are ref counted.
  virtual ~QuicAckListenerInterface() {}
};

}  // namespace net

#endif  // NET_QUIC_QUIC_ACK_LISTENER_INTERFACE_H_
