// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_protocol.h"

#include "base/stl_util.h"
#include "base/strings/string_number_conversions.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using std::map;
using std::numeric_limits;
using std::ostream;
using std::string;

namespace net {

const char* const kFinalOffsetHeaderKey = ":final-offset";

size_t GetPacketHeaderSize(QuicVersion version,
                           const QuicPacketHeader& header) {
  return GetPacketHeaderSize(version, header.public_header.connection_id_length,
                             header.public_header.version_flag,
                             header.public_header.multipath_flag,
                             header.public_header.nonce != nullptr,
                             header.public_header.packet_number_length);
}

size_t GetPacketHeaderSize(QuicVersion version,
                           QuicConnectionIdLength connection_id_length,
                           bool include_version,
                           bool include_path_id,
                           bool include_diversification_nonce,
                           QuicPacketNumberLength packet_number_length) {
  return kPublicFlagsSize + connection_id_length +
         (include_version ? kQuicVersionSize : 0) +
         (include_path_id ? kQuicPathIdSize : 0) + packet_number_length +
         (include_diversification_nonce ? kDiversificationNonceSize : 0) +
         (version <= QUIC_VERSION_33 ? kPrivateFlagsSize : 0);
}

size_t GetStartOfEncryptedData(QuicVersion version,
                               const QuicPacketHeader& header) {
  return GetPacketHeaderSize(version, header) -
         (version <= QUIC_VERSION_33 ? kPrivateFlagsSize : 0);
}

size_t GetStartOfEncryptedData(QuicVersion version,
                               QuicConnectionIdLength connection_id_length,
                               bool include_version,
                               bool include_path_id,
                               bool include_diversification_nonce,
                               QuicPacketNumberLength packet_number_length) {
  // Encryption starts before private flags.
  return GetPacketHeaderSize(version, connection_id_length, include_version,
                             include_path_id, include_diversification_nonce,
                             packet_number_length) -
         (version <= QUIC_VERSION_33 ? kPrivateFlagsSize : 0);
}

QuicPacketPublicHeader::QuicPacketPublicHeader()
    : connection_id(0),
      connection_id_length(PACKET_8BYTE_CONNECTION_ID),
      multipath_flag(false),
      reset_flag(false),
      version_flag(false),
      packet_number_length(PACKET_6BYTE_PACKET_NUMBER),
      nonce(nullptr) {}

QuicPacketPublicHeader::QuicPacketPublicHeader(
    const QuicPacketPublicHeader& other) = default;

QuicPacketPublicHeader::~QuicPacketPublicHeader() {}

QuicPacketHeader::QuicPacketHeader()
    : packet_number(0),
      path_id(kDefaultPathId),
      entropy_flag(false),
      entropy_hash(0),
      fec_flag(false) {}

QuicPacketHeader::QuicPacketHeader(const QuicPacketPublicHeader& header)
    : public_header(header),
      packet_number(0),
      path_id(kDefaultPathId),
      entropy_flag(false),
      entropy_hash(0),
      fec_flag(false) {}

QuicPacketHeader::QuicPacketHeader(const QuicPacketHeader& other) = default;

QuicPublicResetPacket::QuicPublicResetPacket()
    : nonce_proof(0), rejected_packet_number(0) {}

QuicPublicResetPacket::QuicPublicResetPacket(
    const QuicPacketPublicHeader& header)
    : public_header(header), nonce_proof(0), rejected_packet_number(0) {}

QuicBufferAllocator::~QuicBufferAllocator() = default;

void StreamBufferDeleter::operator()(char* buffer) const {
  if (allocator_ != nullptr && buffer != nullptr) {
    allocator_->Delete(buffer);
  }
}

UniqueStreamBuffer NewStreamBuffer(QuicBufferAllocator* allocator,
                                   size_t size) {
  return UniqueStreamBuffer(allocator->New(size),
                            StreamBufferDeleter(allocator));
}

QuicStreamFrame::QuicStreamFrame()
    : QuicStreamFrame(0, false, 0, nullptr, 0, nullptr) {}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 QuicStreamOffset offset,
                                 StringPiece data)
    : QuicStreamFrame(stream_id,
                      fin,
                      offset,
                      data.data(),
                      data.length(),
                      nullptr) {}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 QuicStreamOffset offset,
                                 QuicPacketLength data_length,
                                 UniqueStreamBuffer buffer)
    : QuicStreamFrame(stream_id,
                      fin,
                      offset,
                      nullptr,
                      data_length,
                      std::move(buffer)) {
  DCHECK(this->buffer != nullptr);
  DCHECK_EQ(data_buffer, this->buffer.get());
}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 QuicStreamOffset offset,
                                 const char* data_buffer,
                                 QuicPacketLength data_length,
                                 UniqueStreamBuffer buffer)
    : stream_id(stream_id),
      fin(fin),
      data_length(data_length),
      data_buffer(data_buffer),
      offset(offset),
      buffer(std::move(buffer)) {
  if (this->buffer != nullptr) {
    DCHECK(data_buffer == nullptr);
    this->data_buffer = this->buffer.get();
  }
}

QuicStreamFrame::~QuicStreamFrame() {}

uint32_t MakeQuicTag(char a, char b, char c, char d) {
  return static_cast<uint32_t>(a) | static_cast<uint32_t>(b) << 8 |
         static_cast<uint32_t>(c) << 16 | static_cast<uint32_t>(d) << 24;
}

bool ContainsQuicTag(const QuicTagVector& tag_vector, QuicTag tag) {
  return std::find(tag_vector.begin(), tag_vector.end(), tag) !=
         tag_vector.end();
}

QuicVersionVector QuicSupportedVersions() {
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  return supported_versions;
}

QuicVersionVector FilterSupportedVersions(QuicVersionVector versions) {
  QuicVersionVector filtered_versions(versions.size());
  filtered_versions.clear();  // Guaranteed by spec not to change capacity.
  for (QuicVersion version : versions) {
    if (version < QUIC_VERSION_30) {
      if (!FLAGS_quic_disable_pre_30) {
        filtered_versions.push_back(version);
      }
    } else {
      if (version == QUIC_VERSION_35) {
        if (FLAGS_quic_enable_version_35) {
          filtered_versions.push_back(version);
        }
      } else {
        filtered_versions.push_back(version);
      }
    }
  }
  return filtered_versions;
}

QuicTag QuicVersionToQuicTag(const QuicVersion version) {
  switch (version) {
    case QUIC_VERSION_25:
      return MakeQuicTag('Q', '0', '2', '5');
    case QUIC_VERSION_26:
      return MakeQuicTag('Q', '0', '2', '6');
    case QUIC_VERSION_27:
      return MakeQuicTag('Q', '0', '2', '7');
    case QUIC_VERSION_28:
      return MakeQuicTag('Q', '0', '2', '8');
    case QUIC_VERSION_29:
      return MakeQuicTag('Q', '0', '2', '9');
    case QUIC_VERSION_30:
      return MakeQuicTag('Q', '0', '3', '0');
    case QUIC_VERSION_31:
      return MakeQuicTag('Q', '0', '3', '1');
    case QUIC_VERSION_32:
      return MakeQuicTag('Q', '0', '3', '2');
    case QUIC_VERSION_33:
      return MakeQuicTag('Q', '0', '3', '3');
    case QUIC_VERSION_34:
      return MakeQuicTag('Q', '0', '3', '4');
    case QUIC_VERSION_35:
      return MakeQuicTag('Q', '0', '3', '5');
    default:
      // This shold be an ERROR because we should never attempt to convert an
      // invalid QuicVersion to be written to the wire.
      LOG(ERROR) << "Unsupported QuicVersion: " << version;
      return 0;
  }
}

QuicVersion QuicTagToQuicVersion(const QuicTag version_tag) {
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    if (version_tag == QuicVersionToQuicTag(kSupportedQuicVersions[i])) {
      return kSupportedQuicVersions[i];
    }
  }
  // Reading from the client so this should not be considered an ERROR.
  DVLOG(1) << "Unsupported QuicTag version: "
           << QuicUtils::TagToString(version_tag);
  return QUIC_VERSION_UNSUPPORTED;
}

#define RETURN_STRING_LITERAL(x) \
  case x:                        \
    return #x

string QuicVersionToString(const QuicVersion version) {
  switch (version) {
    RETURN_STRING_LITERAL(QUIC_VERSION_25);
    RETURN_STRING_LITERAL(QUIC_VERSION_26);
    RETURN_STRING_LITERAL(QUIC_VERSION_27);
    RETURN_STRING_LITERAL(QUIC_VERSION_28);
    RETURN_STRING_LITERAL(QUIC_VERSION_29);
    RETURN_STRING_LITERAL(QUIC_VERSION_30);
    RETURN_STRING_LITERAL(QUIC_VERSION_31);
    RETURN_STRING_LITERAL(QUIC_VERSION_32);
    RETURN_STRING_LITERAL(QUIC_VERSION_33);
    RETURN_STRING_LITERAL(QUIC_VERSION_34);
    RETURN_STRING_LITERAL(QUIC_VERSION_35);
    default:
      return "QUIC_VERSION_UNSUPPORTED";
  }
}

string QuicVersionVectorToString(const QuicVersionVector& versions) {
  string result = "";
  for (size_t i = 0; i < versions.size(); ++i) {
    if (i != 0) {
      result.append(",");
    }
    result.append(QuicVersionToString(versions[i]));
  }
  return result;
}

ostream& operator<<(ostream& os, const Perspective& s) {
  if (s == Perspective::IS_SERVER) {
    os << "IS_SERVER";
  } else {
    os << "IS_CLIENT";
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicPacketHeader& header) {
  os << "{ connection_id: " << header.public_header.connection_id
     << ", connection_id_length: " << header.public_header.connection_id_length
     << ", packet_number_length: " << header.public_header.packet_number_length
     << ", multipath_flag: " << header.public_header.multipath_flag
     << ", reset_flag: " << header.public_header.reset_flag
     << ", version_flag: " << header.public_header.version_flag;
  if (header.public_header.version_flag) {
    os << ", version:";
    for (size_t i = 0; i < header.public_header.versions.size(); ++i) {
      os << " ";
      os << QuicVersionToString(header.public_header.versions[i]);
    }
  }
  if (header.public_header.nonce != nullptr) {
    os << ", diversification_nonce: "
       << net::QuicUtils::HexDecode(*header.public_header.nonce);
  }
  os << ", fec_flag: " << header.fec_flag
     << ", entropy_flag: " << header.entropy_flag
     << ", entropy hash: " << static_cast<int>(header.entropy_hash)
     << ", path_id: " << static_cast<int>(header.path_id)
     << ", packet_number: " << header.packet_number << " }\n";
  return os;
}

bool IsAwaitingPacket(const QuicAckFrame& ack_frame,
                      QuicPacketNumber packet_number,
                      QuicPacketNumber peer_least_packet_awaiting_ack) {
  if (ack_frame.missing) {
    return packet_number > ack_frame.largest_observed ||
           ack_frame.packets.Contains(packet_number);
  }
  return packet_number >= peer_least_packet_awaiting_ack &&
         !ack_frame.packets.Contains(packet_number);
}

QuicStopWaitingFrame::QuicStopWaitingFrame()
    : path_id(kDefaultPathId), entropy_hash(0), least_unacked(0) {}

QuicStopWaitingFrame::~QuicStopWaitingFrame() {}

QuicAckFrame::QuicAckFrame()
    : largest_observed(0),
      ack_delay_time(QuicTime::Delta::Infinite()),
      path_id(kDefaultPathId),
      entropy_hash(0),
      is_truncated(false),
      missing(true) {}

QuicAckFrame::QuicAckFrame(const QuicAckFrame& other) = default;

QuicAckFrame::~QuicAckFrame() {}

QuicRstStreamErrorCode AdjustErrorForVersion(QuicRstStreamErrorCode error_code,
                                             QuicVersion /*version*/) {
  return error_code;
}

QuicRstStreamFrame::QuicRstStreamFrame()
    : stream_id(0), error_code(QUIC_STREAM_NO_ERROR), byte_offset(0) {}

QuicRstStreamFrame::QuicRstStreamFrame(QuicStreamId stream_id,
                                       QuicRstStreamErrorCode error_code,
                                       QuicStreamOffset bytes_written)
    : stream_id(stream_id),
      error_code(error_code),
      byte_offset(bytes_written) {}

QuicConnectionCloseFrame::QuicConnectionCloseFrame()
    : error_code(QUIC_NO_ERROR) {}

QuicFrame::QuicFrame() {}

QuicFrame::QuicFrame(QuicPaddingFrame padding_frame)
    : type(PADDING_FRAME), padding_frame(padding_frame) {}

QuicFrame::QuicFrame(QuicStreamFrame* stream_frame)
    : type(STREAM_FRAME), stream_frame(stream_frame) {}

QuicFrame::QuicFrame(QuicAckFrame* frame) : type(ACK_FRAME), ack_frame(frame) {}

QuicFrame::QuicFrame(QuicMtuDiscoveryFrame frame)
    : type(MTU_DISCOVERY_FRAME), mtu_discovery_frame(frame) {}

QuicFrame::QuicFrame(QuicStopWaitingFrame* frame)
    : type(STOP_WAITING_FRAME), stop_waiting_frame(frame) {}

QuicFrame::QuicFrame(QuicPingFrame frame)
    : type(PING_FRAME), ping_frame(frame) {}

QuicFrame::QuicFrame(QuicRstStreamFrame* frame)
    : type(RST_STREAM_FRAME), rst_stream_frame(frame) {}

QuicFrame::QuicFrame(QuicConnectionCloseFrame* frame)
    : type(CONNECTION_CLOSE_FRAME), connection_close_frame(frame) {}

QuicFrame::QuicFrame(QuicGoAwayFrame* frame)
    : type(GOAWAY_FRAME), goaway_frame(frame) {}

QuicFrame::QuicFrame(QuicWindowUpdateFrame* frame)
    : type(WINDOW_UPDATE_FRAME), window_update_frame(frame) {}

QuicFrame::QuicFrame(QuicBlockedFrame* frame)
    : type(BLOCKED_FRAME), blocked_frame(frame) {}

QuicFrame::QuicFrame(QuicPathCloseFrame* frame)
    : type(PATH_CLOSE_FRAME), path_close_frame(frame) {}

ostream& operator<<(ostream& os, const QuicStopWaitingFrame& sent_info) {
  os << "{ entropy_hash: " << static_cast<int>(sent_info.entropy_hash)
     << ", least_unacked: " << sent_info.least_unacked << " }\n";
  return os;
}

PacketNumberQueue::const_iterator::const_iterator(
    IntervalSet<QuicPacketNumber>::const_iterator interval_set_iter,
    QuicPacketNumber first,
    QuicPacketNumber last)
    : interval_set_iter_(std::move(interval_set_iter)),
      current_(first),
      last_(last) {}

PacketNumberQueue::const_iterator::const_iterator(const const_iterator& other) =
    default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::const_iterator::const_iterator(const_iterator&& other) =
//    default;
PacketNumberQueue::const_iterator::~const_iterator() {}

PacketNumberQueue::const_iterator& PacketNumberQueue::const_iterator::operator=(
    const const_iterator& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::const_iterator&
// PacketNumberQueue::const_iterator::operator=(
//    const_iterator&& other) = default;

bool PacketNumberQueue::const_iterator::operator!=(
    const const_iterator& other) const {
  return current_ != other.current_;
}

bool PacketNumberQueue::const_iterator::operator==(
    const const_iterator& other) const {
  return current_ == other.current_;
}

PacketNumberQueue::const_iterator::value_type
    PacketNumberQueue::const_iterator::operator*() const {
  return current_;
}

PacketNumberQueue::const_iterator& PacketNumberQueue::const_iterator::
operator++() {
  ++current_;
  if (current_ < last_) {
    if (current_ >= interval_set_iter_->max()) {
      ++interval_set_iter_;
      current_ = interval_set_iter_->min();
    }
  } else {
    current_ = last_;
  }
  return *this;
}

PacketNumberQueue::const_iterator PacketNumberQueue::const_iterator::operator++(
    int /* postincrement */) {
  PacketNumberQueue::const_iterator preincrement(*this);
  operator++();
  return preincrement;
}

PacketNumberQueue::PacketNumberQueue() = default;
PacketNumberQueue::PacketNumberQueue(const PacketNumberQueue& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue::PacketNumberQueue(PacketNumberQueue&& other) = default;
PacketNumberQueue::~PacketNumberQueue() {}

PacketNumberQueue& PacketNumberQueue::operator=(
    const PacketNumberQueue& other) = default;
// TODO(rtenneti): on windows RValue reference gives errors.
// PacketNumberQueue& PacketNumberQueue::operator=(PacketNumberQueue&& other) =
//    default;

void PacketNumberQueue::Add(QuicPacketNumber packet_number) {
  packet_number_intervals_.Add(packet_number, packet_number + 1);
}

void PacketNumberQueue::Add(QuicPacketNumber lower, QuicPacketNumber higher) {
  packet_number_intervals_.Add(lower, higher);
}

void PacketNumberQueue::Remove(QuicPacketNumber packet_number) {
  packet_number_intervals_.Difference(packet_number, packet_number + 1);
}

void PacketNumberQueue::Remove(QuicPacketNumber lower,
                               QuicPacketNumber higher) {
  packet_number_intervals_.Difference(lower, higher);
}

bool PacketNumberQueue::RemoveUpTo(QuicPacketNumber higher) {
  if (Empty()) {
    return false;
  }
  const QuicPacketNumber old_min = Min();
  packet_number_intervals_.Difference(0, higher);
  return Empty() || old_min != Min();
}

bool PacketNumberQueue::Contains(QuicPacketNumber packet_number) const {
  return packet_number_intervals_.Contains(packet_number);
}

bool PacketNumberQueue::Empty() const {
  return packet_number_intervals_.Empty();
}

QuicPacketNumber PacketNumberQueue::Min() const {
  DCHECK(!Empty());
  return packet_number_intervals_.begin()->min();
}

QuicPacketNumber PacketNumberQueue::Max() const {
  DCHECK(!Empty());
  return packet_number_intervals_.rbegin()->max() - 1;
}

size_t PacketNumberQueue::NumPacketsSlow() const {
  size_t num_packets = 0;
  for (const auto& interval : packet_number_intervals_) {
    num_packets += interval.Length();
  }
  return num_packets;
}

size_t PacketNumberQueue::NumIntervals() const {
  return packet_number_intervals_.Size();
}

QuicPacketNumber PacketNumberQueue::LastIntervalLength() const {
  DCHECK(!Empty());
  return packet_number_intervals_.rbegin()->Length();
}

PacketNumberQueue::const_iterator PacketNumberQueue::begin() const {
  QuicPacketNumber first;
  QuicPacketNumber last;
  if (packet_number_intervals_.Empty()) {
    first = 0;
    last = 0;
  } else {
    first = packet_number_intervals_.begin()->min();
    last = packet_number_intervals_.rbegin()->max();
  }
  return const_iterator(packet_number_intervals_.begin(), first, last);
}

PacketNumberQueue::const_iterator PacketNumberQueue::end() const {
  QuicPacketNumber last = packet_number_intervals_.Empty()
                              ? 0
                              : packet_number_intervals_.rbegin()->max();
  return const_iterator(packet_number_intervals_.end(), last, last);
}

PacketNumberQueue::const_iterator PacketNumberQueue::lower_bound(
    QuicPacketNumber packet_number) const {
  QuicPacketNumber first;
  QuicPacketNumber last;
  if (packet_number_intervals_.Empty()) {
    first = 0;
    last = 0;
    return const_iterator(packet_number_intervals_.begin(), first, last);
  }
  if (!packet_number_intervals_.Contains(packet_number)) {
    return end();
  }
  IntervalSet<QuicPacketNumber>::const_iterator it =
      packet_number_intervals_.Find(packet_number);
  first = packet_number;
  last = packet_number_intervals_.rbegin()->max();
  return const_iterator(it, first, last);
}

ostream& operator<<(ostream& os, const PacketNumberQueue& q) {
  for (QuicPacketNumber packet_number : q) {
    os << packet_number << " ";
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicAckFrame& ack_frame) {
  os << "{ entropy_hash: " << static_cast<int>(ack_frame.entropy_hash)
     << ", largest_observed: " << ack_frame.largest_observed
     << ", ack_delay_time: " << ack_frame.ack_delay_time.ToMicroseconds()
     << ", packets: [ " << ack_frame.packets << " ]"
     << ", is_truncated: " << ack_frame.is_truncated
     << ", received_packets: [ ";
  for (const std::pair<QuicPacketNumber, QuicTime>& p :
       ack_frame.received_packet_times) {
    os << p.first << " at " << p.second.ToDebuggingValue() << " ";
  }
  os << " ] }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicFrame& frame) {
  switch (frame.type) {
    case PADDING_FRAME: {
      os << "type { PADDING_FRAME } " << frame.padding_frame;
      break;
    }
    case RST_STREAM_FRAME: {
      os << "type { RST_STREAM_FRAME } " << *(frame.rst_stream_frame);
      break;
    }
    case CONNECTION_CLOSE_FRAME: {
      os << "type { CONNECTION_CLOSE_FRAME } "
         << *(frame.connection_close_frame);
      break;
    }
    case GOAWAY_FRAME: {
      os << "type { GOAWAY_FRAME } " << *(frame.goaway_frame);
      break;
    }
    case WINDOW_UPDATE_FRAME: {
      os << "type { WINDOW_UPDATE_FRAME } " << *(frame.window_update_frame);
      break;
    }
    case BLOCKED_FRAME: {
      os << "type { BLOCKED_FRAME } " << *(frame.blocked_frame);
      break;
    }
    case STREAM_FRAME: {
      os << "type { STREAM_FRAME } " << *(frame.stream_frame);
      break;
    }
    case ACK_FRAME: {
      os << "type { ACK_FRAME } " << *(frame.ack_frame);
      break;
    }
    case STOP_WAITING_FRAME: {
      os << "type { STOP_WAITING_FRAME } " << *(frame.stop_waiting_frame);
      break;
    }
    case PING_FRAME: {
      os << "type { PING_FRAME } ";
      break;
    }
    case MTU_DISCOVERY_FRAME: {
      os << "type { MTU_DISCOVERY_FRAME } ";
      break;
    }
    case PATH_CLOSE_FRAME: {
      os << "type { PATH_CLOSE_FRAME } " << *(frame.path_close_frame);
      break;
    }
    default: {
      LOG(ERROR) << "Unknown frame type: " << frame.type;
      break;
    }
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicPaddingFrame& padding_frame) {
  os << "{ num_padding_bytes: " << padding_frame.num_padding_bytes << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicRstStreamFrame& rst_frame) {
  os << "{ stream_id: " << rst_frame.stream_id
     << ", error_code: " << rst_frame.error_code << " }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicConnectionCloseFrame& connection_close_frame) {
  os << "{ error_code: " << connection_close_frame.error_code
     << ", error_details: '" << connection_close_frame.error_details << "' }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicGoAwayFrame& goaway_frame) {
  os << "{ error_code: " << goaway_frame.error_code
     << ", last_good_stream_id: " << goaway_frame.last_good_stream_id
     << ", reason_phrase: '" << goaway_frame.reason_phrase << "' }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicWindowUpdateFrame& window_update_frame) {
  os << "{ stream_id: " << window_update_frame.stream_id
     << ", byte_offset: " << window_update_frame.byte_offset << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicBlockedFrame& blocked_frame) {
  os << "{ stream_id: " << blocked_frame.stream_id << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicPathCloseFrame& path_close_frame) {
  os << "{ path_id: " << static_cast<int>(path_close_frame.path_id) << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicStreamFrame& stream_frame) {
  os << "{ stream_id: " << stream_frame.stream_id
     << ", fin: " << stream_frame.fin << ", offset: " << stream_frame.offset
     << ", length: " << stream_frame.data_length << " }\n";
  return os;
}

QuicGoAwayFrame::QuicGoAwayFrame()
    : error_code(QUIC_NO_ERROR), last_good_stream_id(0) {}

QuicGoAwayFrame::QuicGoAwayFrame(QuicErrorCode error_code,
                                 QuicStreamId last_good_stream_id,
                                 const string& reason)
    : error_code(error_code),
      last_good_stream_id(last_good_stream_id),
      reason_phrase(reason) {}

QuicData::QuicData(const char* buffer, size_t length)
    : buffer_(buffer), length_(length), owns_buffer_(false) {}

QuicData::QuicData(char* buffer, size_t length, bool owns_buffer)
    : buffer_(buffer), length_(length), owns_buffer_(owns_buffer) {}

QuicData::~QuicData() {
  if (owns_buffer_) {
    delete[] const_cast<char*>(buffer_);
  }
}

QuicWindowUpdateFrame::QuicWindowUpdateFrame(QuicStreamId stream_id,
                                             QuicStreamOffset byte_offset)
    : stream_id(stream_id), byte_offset(byte_offset) {}

QuicBlockedFrame::QuicBlockedFrame(QuicStreamId stream_id)
    : stream_id(stream_id) {}

QuicPathCloseFrame::QuicPathCloseFrame(QuicPathId path_id) : path_id(path_id) {}

QuicPacket::QuicPacket(char* buffer,
                       size_t length,
                       bool owns_buffer,
                       QuicConnectionIdLength connection_id_length,
                       bool includes_version,
                       bool includes_path_id,
                       bool includes_diversification_nonce,
                       QuicPacketNumberLength packet_number_length)
    : QuicData(buffer, length, owns_buffer),
      buffer_(buffer),
      connection_id_length_(connection_id_length),
      includes_version_(includes_version),
      includes_path_id_(includes_path_id),
      includes_diversification_nonce_(includes_diversification_nonce),
      packet_number_length_(packet_number_length) {}

QuicEncryptedPacket::QuicEncryptedPacket(const char* buffer, size_t length)
    : QuicData(buffer, length) {}

QuicEncryptedPacket::QuicEncryptedPacket(char* buffer,
                                         size_t length,
                                         bool owns_buffer)
    : QuicData(buffer, length, owns_buffer) {}

QuicEncryptedPacket* QuicEncryptedPacket::Clone() const {
  char* buffer = new char[this->length()];
  memcpy(buffer, this->data(), this->length());
  return new QuicEncryptedPacket(buffer, this->length(), true);
}

ostream& operator<<(ostream& os, const QuicEncryptedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

QuicReceivedPacket::QuicReceivedPacket(const char* buffer,
                                       size_t length,
                                       QuicTime receipt_time)
    : QuicEncryptedPacket(buffer, length), receipt_time_(receipt_time) {}

QuicReceivedPacket::QuicReceivedPacket(char* buffer,
                                       size_t length,
                                       QuicTime receipt_time,
                                       bool owns_buffer)
    : QuicEncryptedPacket(buffer, length, owns_buffer),
      receipt_time_(receipt_time) {}

QuicReceivedPacket* QuicReceivedPacket::Clone() const {
  char* buffer = new char[this->length()];
  memcpy(buffer, this->data(), this->length());
  return new QuicReceivedPacket(buffer, this->length(), receipt_time(), true);
}

ostream& operator<<(ostream& os, const QuicReceivedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

StringPiece QuicPacket::AssociatedData(QuicVersion version) const {
  return StringPiece(
      data(), GetStartOfEncryptedData(version, connection_id_length_,
                                      includes_version_, includes_path_id_,
                                      includes_diversification_nonce_,
                                      packet_number_length_));
}

StringPiece QuicPacket::Plaintext(QuicVersion version) const {
  const size_t start_of_encrypted_data = GetStartOfEncryptedData(
      version, connection_id_length_, includes_version_, includes_path_id_,
      includes_diversification_nonce_, packet_number_length_);
  return StringPiece(data() + start_of_encrypted_data,
                     length() - start_of_encrypted_data);
}

AckListenerWrapper::AckListenerWrapper(QuicAckListenerInterface* listener,
                                       QuicPacketLength data_length)
    : ack_listener(listener), length(data_length) {
  DCHECK(listener != nullptr);
}

AckListenerWrapper::AckListenerWrapper(const AckListenerWrapper& other) =
    default;

AckListenerWrapper::~AckListenerWrapper() {}

SerializedPacket::SerializedPacket(QuicPathId path_id,
                                   QuicPacketNumber packet_number,
                                   QuicPacketNumberLength packet_number_length,
                                   const char* encrypted_buffer,
                                   QuicPacketLength encrypted_length,
                                   QuicPacketEntropyHash entropy_hash,
                                   bool has_ack,
                                   bool has_stop_waiting)
    : encrypted_buffer(encrypted_buffer),
      encrypted_length(encrypted_length),
      has_crypto_handshake(NOT_HANDSHAKE),
      num_padding_bytes(0),
      path_id(path_id),
      packet_number(packet_number),
      packet_number_length(packet_number_length),
      encryption_level(ENCRYPTION_NONE),
      entropy_hash(entropy_hash),
      has_ack(has_ack),
      has_stop_waiting(has_stop_waiting),
      transmission_type(NOT_RETRANSMISSION),
      original_path_id(kInvalidPathId),
      original_packet_number(0) {}

SerializedPacket::SerializedPacket(const SerializedPacket& other) = default;

SerializedPacket::~SerializedPacket() {}

TransmissionInfo::TransmissionInfo()
    : encryption_level(ENCRYPTION_NONE),
      packet_number_length(PACKET_1BYTE_PACKET_NUMBER),
      bytes_sent(0),
      sent_time(QuicTime::Zero()),
      transmission_type(NOT_RETRANSMISSION),
      in_flight(false),
      is_unackable(false),
      has_crypto_handshake(false),
      num_padding_bytes(0),
      retransmission(0) {}

TransmissionInfo::TransmissionInfo(EncryptionLevel level,
                                   QuicPacketNumberLength packet_number_length,
                                   TransmissionType transmission_type,
                                   QuicTime sent_time,
                                   QuicPacketLength bytes_sent,
                                   bool has_crypto_handshake,
                                   int num_padding_bytes)
    : encryption_level(level),
      packet_number_length(packet_number_length),
      bytes_sent(bytes_sent),
      sent_time(sent_time),
      transmission_type(transmission_type),
      in_flight(false),
      is_unackable(false),
      has_crypto_handshake(has_crypto_handshake),
      num_padding_bytes(num_padding_bytes),
      retransmission(0) {}

TransmissionInfo::TransmissionInfo(const TransmissionInfo& other) = default;

TransmissionInfo::~TransmissionInfo() {}

}  // namespace net
