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
    //  num_original_packets - Number of packets in the original transmission.
    //  num_original_bytes - Number of packets in the original transmission.
    //  num_retransmitted_packets - Number of packets that had to be
    //                              retransmitted.
    //  num_retransmitted_bytes - Number of bytes that had to be retransmitted.
    virtual void OnAckNotification(int num_original_packets,
                                   int num_original_bytes,
                                   int num_retransmitted_packets,
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

  // Register a sequence number that this AckNotifier should be interested in.
  void AddSequenceNumber(const QuicPacketSequenceNumber& sequence_number,
                         int packet_payload_size);

  // Called by the QuicConnection on receipt of new ACK frame, with the sequence
  // number referenced by the ACK frame.
  // Deletes the matching sequence number from the stored set of sequence
  // numbers. If this set is now empty, call the stored delegate's
  // OnAckNotification method.
  //
  // Returns true if the provided sequence_number caused the delegate to be
  // called, false otherwise.
  bool OnAck(QuicPacketSequenceNumber sequence_number,
             QuicTime::Delta delta_largest_observed);

  bool IsEmpty() { return sequence_numbers_.empty(); }

  // If a packet is retransmitted by the connection it will be sent with a
  // different sequence number. Updates our internal set of sequence_numbers to
  // track the latest number.
  void UpdateSequenceNumber(QuicPacketSequenceNumber old_sequence_number,
                            QuicPacketSequenceNumber new_sequence_number);

 private:
  struct PacketInfo {
    PacketInfo();
    explicit PacketInfo(int payload_size);

    int packet_payload_size;
  };

  // The delegate's OnAckNotification() method will be called once we have been
  // notified of ACKs for all the sequence numbers we are tracking.
  // This is not owned by OnAckNotifier and must outlive it.
  scoped_refptr<DelegateInterface> delegate_;

  // Sequence numbers this notifier is waiting to hear about. The
  // delegate will not be called until this is empty.
  base::hash_map<QuicPacketSequenceNumber, PacketInfo> sequence_numbers_;

  // Transmission and retransmission stats.
  // Number of packets in the original transmission.
  int original_packet_count_;
  // Number of packets in the original transmission.
  int original_byte_count_;
  // Number of packets that had to be retransmitted.
  int retransmitted_packet_count_;
  // Number of bytes that had to be retransmitted.
  int retransmitted_byte_count_;

  DISALLOW_COPY_AND_ASSIGN(QuicAckNotifier);
};

};  // namespace net

#endif  // NET_QUIC_QUIC_ACK_NOTIFIER_H_
