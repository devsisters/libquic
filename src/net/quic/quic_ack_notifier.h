// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_ACK_NOTIFIER_H_
#define NET_QUIC_QUIC_ACK_NOTIFIER_H_

#include "base/memory/ref_counted.h"
#include "net/quic/quic_protocol.h"

namespace net {

// Used to register with a QuicConnection for notification once a set of packets
// have all been ACKed.
// The connection informs this class of newly ACKed sequence numbers, and once
// we have seen ACKs for all the sequence numbers we are interested in, we
// trigger a call to a provided Closure.
class NET_EXPORT_PRIVATE QuicAckNotifier {
 public:
  class NET_EXPORT_PRIVATE DelegateInterface
      : public base::RefCounted<DelegateInterface> {
   public:
    DelegateInterface();
    // Args:
    //  num_retransmitted_packets - Number of packets that had to be
    //                              retransmitted.
    //  num_retransmitted_bytes - Number of bytes that had to be retransmitted.
    virtual void OnAckNotification(int num_retransmitted_packets,
                                   int num_retransmitted_bytes,
                                   QuicTime::Delta delta_largest_observed) = 0;

   protected:
    friend class base::RefCounted<DelegateInterface>;

    // Delegates are ref counted.
    virtual ~DelegateInterface();
  };

  // QuicAckNotifier is expected to keep its own reference to the delegate.
  explicit QuicAckNotifier(DelegateInterface* delegate);
  virtual ~QuicAckNotifier();

  // Register a serialized packet the notifier should track.
  void OnSerializedPacket();

  // Called on receipt of new ACK frame for an unacked packet.
  // Decrements the number of unacked packets and if there are none left, calls
  // the stored delegate's OnAckNotification method.
  //
  // Returns true if the delegate was called, false otherwise.
  bool OnAck(QuicTime::Delta delta_largest_observed);

  // Called when we've given up waiting for a sequence number, typically when
  // the connection is torn down.
  // Returns true if there are no more unacked packets being tracked.
  bool OnPacketAbandoned();

  bool HasUnackedPackets() const { return unacked_packets_ > 0; }

  // If a packet is retransmitted by the connection, it will be sent with a
  // different sequence number.
  void OnPacketRetransmitted(int packet_payload_size);

 private:
  // The delegate's OnAckNotification() method will be called once we have been
  // notified of ACKs for all the sequence numbers we are tracking.
  // This is not owned by OnAckNotifier and must outlive it.
  scoped_refptr<DelegateInterface> delegate_;

  // The number of unacked packets being tracked.
  int unacked_packets_;

  // Number of packets that had to be retransmitted.
  int retransmitted_packet_count_;
  // Number of bytes that had to be retransmitted.
  int retransmitted_byte_count_;

  DISALLOW_COPY_AND_ASSIGN(QuicAckNotifier);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_ACK_NOTIFIER_H_
