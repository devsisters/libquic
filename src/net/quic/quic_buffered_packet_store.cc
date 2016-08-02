// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_buffered_packet_store.h"

#include <list>

#include "base/stl_util.h"

using std::list;

namespace net {

typedef QuicBufferedPacketStore::BufferedPacket BufferedPacket;
typedef QuicBufferedPacketStore::EnqueuePacketResult EnqueuePacketResult;
typedef QuicBufferedPacketStore::BufferedPacketList BufferedPacketList;

// Max number of connections this store can keep track.
static const size_t kDefaultMaxConnectionsInStore = 100;

namespace {

// This alarm removes expired entries in map each time this alarm fires.
class ConnectionExpireAlarm : public QuicAlarm::Delegate {
 public:
  explicit ConnectionExpireAlarm(QuicBufferedPacketStore* store)
      : connection_store_(store) {}

  void OnAlarm() override { connection_store_->OnExpirationTimeout(); }

  // Disallow copy and asign.
  ConnectionExpireAlarm(const ConnectionExpireAlarm&) = delete;
  ConnectionExpireAlarm& operator=(const ConnectionExpireAlarm&) = delete;

 private:
  QuicBufferedPacketStore* connection_store_;
};

}  // namespace

BufferedPacket::BufferedPacket(std::unique_ptr<QuicReceivedPacket> packet,
                               IPEndPoint server_address,
                               IPEndPoint client_address)
    : packet(std::move(packet)),
      server_address(server_address),
      client_address(client_address) {}

BufferedPacket::BufferedPacket(BufferedPacket&& other) = default;

BufferedPacket& BufferedPacket::operator=(BufferedPacket&& other) = default;

BufferedPacket::~BufferedPacket() {}

BufferedPacketList::BufferedPacketList() : creation_time(QuicTime::Zero()) {}

BufferedPacketList::BufferedPacketList(BufferedPacketList&& other) = default;

BufferedPacketList& BufferedPacketList::operator=(BufferedPacketList&& other) =
    default;

BufferedPacketList::~BufferedPacketList() {}

QuicBufferedPacketStore::QuicBufferedPacketStore(
    VisitorInterface* visitor,
    const QuicClock* clock,
    QuicAlarmFactory* alarm_factory)
    : connection_life_span_(
          QuicTime::Delta::FromSeconds(kInitialIdleTimeoutSecs)),
      visitor_(visitor),
      clock_(clock),
      expiration_alarm_(
          alarm_factory->CreateAlarm(new ConnectionExpireAlarm(this))) {}

QuicBufferedPacketStore::~QuicBufferedPacketStore() {}

EnqueuePacketResult QuicBufferedPacketStore::EnqueuePacket(
    QuicConnectionId connection_id,
    const QuicReceivedPacket& packet,
    IPEndPoint server_address,
    IPEndPoint client_address) {
  if (!ContainsKey(undecryptable_packets_, connection_id) &&
      undecryptable_packets_.size() >= kDefaultMaxConnectionsInStore) {
    // Drop the packet if store can't keep track of more connections.
    return TOO_MANY_CONNECTIONS;
  } else if (!ContainsKey(undecryptable_packets_, connection_id)) {
    undecryptable_packets_.emplace(
        std::make_pair(connection_id, BufferedPacketList()));
  }
  CHECK(ContainsKey(undecryptable_packets_, connection_id));
  BufferedPacketList& queue =
      undecryptable_packets_.find(connection_id)->second;

  if (queue.buffered_packets.size() >= kDefaultMaxUndecryptablePackets) {
    // If there are kMaxBufferedPacketsPerConnection packets buffered up for
    // this connection, drop the current packet.
    return TOO_MANY_PACKETS;
  }

  if (queue.buffered_packets.empty()) {
    // If this is the first packet arrived on a new connection, initialize the
    // creation time.
    queue.creation_time = clock_->ApproximateNow();
  }

  BufferedPacket new_entry(std::unique_ptr<QuicReceivedPacket>(packet.Clone()),
                           server_address, client_address);

  queue.buffered_packets.push_back(std::move(new_entry));

  if (!expiration_alarm_->IsSet()) {
    expiration_alarm_->Set(clock_->ApproximateNow() + connection_life_span_);
  }
  return SUCCESS;
}

bool QuicBufferedPacketStore::HasBufferedPackets(
    QuicConnectionId connection_id) const {
  return ContainsKey(undecryptable_packets_, connection_id);
}

list<BufferedPacket> QuicBufferedPacketStore::DeliverPackets(
    QuicConnectionId connection_id) {
  list<BufferedPacket> packets_to_deliver;
  auto it = undecryptable_packets_.find(connection_id);
  if (it != undecryptable_packets_.end()) {
    packets_to_deliver = std::move(it->second.buffered_packets);
    undecryptable_packets_.erase(connection_id);
  }
  return packets_to_deliver;
}

void QuicBufferedPacketStore::OnExpirationTimeout() {
  QuicTime expiration_time = clock_->ApproximateNow() - connection_life_span_;
  while (!undecryptable_packets_.empty()) {
    auto& entry = undecryptable_packets_.front();
    if (entry.second.creation_time > expiration_time) {
      break;
    }
    visitor_->OnExpiredPackets(entry.first, std::move(entry.second));
    undecryptable_packets_.erase(undecryptable_packets_.begin());
  }
  if (!undecryptable_packets_.empty()) {
    expiration_alarm_->Set(clock_->ApproximateNow() + connection_life_span_);
  }
}

}  // namespace net
