// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_BUFFERED_PACKET_STORE_H_
#define NET_QUIC_QUIC_BUFFERED_PACKET_STORE_H_

#include "net/base/ip_address.h"
#include "net/base/linked_hash_map.h"
#include "net/quic/quic_alarm.h"
#include "net/quic/quic_alarm_factory.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_time.h"

namespace net {

namespace test {
class QuicBufferedPacketStorePeer;
}  // namespace test

// This class buffers undeliverable packets for each connection until either
// 1) They are requested to be delivered via DeliverPacket(), or
// 2) They expire after exceeding their lifetime in the store.
class NET_EXPORT_PRIVATE QuicBufferedPacketStore {
 public:
  enum EnqueuePacketResult {
    SUCCESS = 0,
    TOO_MANY_PACKETS,  // Too many packets stored up for a certain connection.
    TOO_MANY_CONNECTIONS  // Too many connections stored up in the store.
  };

  // A packets with client/server address.
  struct NET_EXPORT_PRIVATE BufferedPacket {
    BufferedPacket(std::unique_ptr<QuicReceivedPacket> packet,
                   IPEndPoint server_address,
                   IPEndPoint client_address);
    BufferedPacket(BufferedPacket&& other);

    BufferedPacket& operator=(BufferedPacket&& other);

    ~BufferedPacket();

    std::unique_ptr<QuicReceivedPacket> packet;
    IPEndPoint server_address;
    IPEndPoint client_address;
  };

  // A queue of BufferedPackets for a connection.
  struct NET_EXPORT_PRIVATE BufferedPacketList {
    BufferedPacketList();
    BufferedPacketList(BufferedPacketList&& other);

    BufferedPacketList& operator=(BufferedPacketList&& other);

    ~BufferedPacketList();

    std::list<BufferedPacket> buffered_packets;
    QuicTime creation_time;
  };

  typedef linked_hash_map<QuicConnectionId, BufferedPacketList>
      BufferedPacketMap;

  class NET_EXPORT_PRIVATE VisitorInterface {
   public:
    virtual ~VisitorInterface() {}

    // Called for each expired connection when alarm fires.
    virtual void OnExpiredPackets(QuicConnectionId connection_id,
                                  BufferedPacketList early_arrived_packets) = 0;
  };

  QuicBufferedPacketStore(VisitorInterface* vistor,
                          const QuicClock* clock,
                          QuicAlarmFactory* alarm_factory);

  QuicBufferedPacketStore(const QuicBufferedPacketStore&) = delete;

  ~QuicBufferedPacketStore();

  QuicBufferedPacketStore& operator=(const QuicBufferedPacketStore&) = delete;

  // Adds a copy of packet into packet queue for given connection.
  EnqueuePacketResult EnqueuePacket(QuicConnectionId connection_id,
                                    const QuicReceivedPacket& packet,
                                    IPEndPoint server_address,
                                    IPEndPoint client_address);

  // Returns true if there are any packets buffered for |connection_id|.
  bool HasBufferedPackets(QuicConnectionId connection_id) const;

  // Returns the list of buffered packets for |connection_id| and removes them
  // from the store. Returns an empty list if no early arrived packets for this
  // connection are present.
  std::list<BufferedPacket> DeliverPackets(QuicConnectionId connection_id);

  // Examines how long packets have been buffered in the store for each
  // connection. If they stay too long, removes them for new coming packets and
  // calls |visitor_|'s OnPotentialConnectionExpire().
  // Resets the alarm at the end.
  void OnExpirationTimeout();

 private:
  friend class test::QuicBufferedPacketStorePeer;

  // A map to store packet queues with creation time for each connection.
  BufferedPacketMap undecryptable_packets_;

  // The max time the packets of a connection can be buffer in the store.
  QuicTime::Delta connection_life_span_;

  VisitorInterface* visitor_;  // Unowned.

  const QuicClock* clock_;  // Unowned.

  // This alarm fires every |connection_life_span_| to clean up
  // packets staying in the store for too long.
  std::unique_ptr<QuicAlarm> expiration_alarm_;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_BUFFERED_PACKET_STORE_H_
