// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_protocol.h"

#include "base/stl_util.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;
using std::map;
using std::numeric_limits;
using std::ostream;
using std::string;

namespace net {

size_t GetPacketHeaderSize(const QuicPacketHeader& header) {
  return GetPacketHeaderSize(header.public_header.connection_id_length,
                             header.public_header.version_flag,
                             header.public_header.sequence_number_length,
                             header.is_in_fec_group);
}

size_t GetPacketHeaderSize(QuicConnectionIdLength connection_id_length,
                           bool include_version,
                           QuicSequenceNumberLength sequence_number_length,
                           InFecGroup is_in_fec_group) {
  return kPublicFlagsSize + connection_id_length +
      (include_version ? kQuicVersionSize : 0) + sequence_number_length +
      kPrivateFlagsSize + (is_in_fec_group == IN_FEC_GROUP ? kFecGroupSize : 0);
}

size_t GetStartOfFecProtectedData(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    QuicSequenceNumberLength sequence_number_length) {
  return GetPacketHeaderSize(connection_id_length,
                             include_version,
                             sequence_number_length,
                             IN_FEC_GROUP);
}

size_t GetStartOfEncryptedData(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    QuicSequenceNumberLength sequence_number_length) {
  // Don't include the fec size, since encryption starts before private flags.
  return GetPacketHeaderSize(connection_id_length,
                             include_version,
                             sequence_number_length,
                             NOT_IN_FEC_GROUP) - kPrivateFlagsSize;
}

QuicPacketPublicHeader::QuicPacketPublicHeader()
    : connection_id(0),
      connection_id_length(PACKET_8BYTE_CONNECTION_ID),
      reset_flag(false),
      version_flag(false),
      sequence_number_length(PACKET_6BYTE_SEQUENCE_NUMBER) {
}

QuicPacketPublicHeader::QuicPacketPublicHeader(
    const QuicPacketPublicHeader& other)
    : connection_id(other.connection_id),
      connection_id_length(other.connection_id_length),
      reset_flag(other.reset_flag),
      version_flag(other.version_flag),
      sequence_number_length(other.sequence_number_length),
      versions(other.versions) {
}

QuicPacketPublicHeader::~QuicPacketPublicHeader() {}

QuicPacketHeader::QuicPacketHeader()
    : fec_flag(false),
      entropy_flag(false),
      entropy_hash(0),
      packet_sequence_number(0),
      is_in_fec_group(NOT_IN_FEC_GROUP),
      fec_group(0) {
}

QuicPacketHeader::QuicPacketHeader(const QuicPacketPublicHeader& header)
    : public_header(header),
      fec_flag(false),
      entropy_flag(false),
      entropy_hash(0),
      packet_sequence_number(0),
      is_in_fec_group(NOT_IN_FEC_GROUP),
      fec_group(0) {
}

QuicPublicResetPacket::QuicPublicResetPacket()
    : nonce_proof(0),
      rejected_sequence_number(0) {}

QuicPublicResetPacket::QuicPublicResetPacket(
    const QuicPacketPublicHeader& header)
    : public_header(header),
      nonce_proof(0),
      rejected_sequence_number(0) {}

QuicStreamFrame::QuicStreamFrame() : stream_id(0), fin(false), offset(0) {
}

QuicStreamFrame::QuicStreamFrame(const QuicStreamFrame& frame)
    : stream_id(frame.stream_id),
      fin(frame.fin),
      offset(frame.offset),
      data(frame.data) {
}

QuicStreamFrame::QuicStreamFrame(QuicStreamId stream_id,
                                 bool fin,
                                 QuicStreamOffset offset,
                                 IOVector data)
    : stream_id(stream_id), fin(fin), offset(offset), data(data) {
}

string* QuicStreamFrame::GetDataAsString() const {
  string* data_string = new string();
  data_string->reserve(data.TotalBufferSize());
  for (size_t i = 0; i < data.Size(); ++i) {
    data_string->append(static_cast<char*>(data.iovec()[i].iov_base),
                        data.iovec()[i].iov_len);
  }
  DCHECK_EQ(data_string->size(), data.TotalBufferSize());
  return data_string;
}

uint32 MakeQuicTag(char a, char b, char c, char d) {
  return static_cast<uint32>(a) |
         static_cast<uint32>(b) << 8 |
         static_cast<uint32>(c) << 16 |
         static_cast<uint32>(d) << 24;
}

bool ContainsQuicTag(const QuicTagVector& tag_vector, QuicTag tag) {
  return std::find(tag_vector.begin(), tag_vector.end(),  tag)
      != tag_vector.end();
}

QuicVersionVector QuicSupportedVersions() {
  QuicVersionVector supported_versions;
  for (size_t i = 0; i < arraysize(kSupportedQuicVersions); ++i) {
    supported_versions.push_back(kSupportedQuicVersions[i]);
  }
  return supported_versions;
}

QuicTag QuicVersionToQuicTag(const QuicVersion version) {
  switch (version) {
    case QUIC_VERSION_23:
      return MakeQuicTag('Q', '0', '2', '3');
    case QUIC_VERSION_24:
      return MakeQuicTag('Q', '0', '2', '4');
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
case x: \
return #x

string QuicVersionToString(const QuicVersion version) {
  switch (version) {
    RETURN_STRING_LITERAL(QUIC_VERSION_23);
    RETURN_STRING_LITERAL(QUIC_VERSION_24);
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

ostream& operator<<(ostream& os, const QuicPacketHeader& header) {
  os << "{ connection_id: " << header.public_header.connection_id
     << ", connection_id_length:" << header.public_header.connection_id_length
     << ", sequence_number_length:"
     << header.public_header.sequence_number_length
     << ", reset_flag: " << header.public_header.reset_flag
     << ", version_flag: " << header.public_header.version_flag;
  if (header.public_header.version_flag) {
    os << " version: ";
    for (size_t i = 0; i < header.public_header.versions.size(); ++i) {
      os << header.public_header.versions[0] << " ";
    }
  }
  os << ", fec_flag: " << header.fec_flag
     << ", entropy_flag: " << header.entropy_flag
     << ", entropy hash: " << static_cast<int>(header.entropy_hash)
     << ", sequence_number: " << header.packet_sequence_number
     << ", is_in_fec_group:" << header.is_in_fec_group
     << ", fec_group: " << header.fec_group<< "}\n";
  return os;
}

bool IsAwaitingPacket(const QuicAckFrame& ack_frame,
                      QuicPacketSequenceNumber sequence_number) {
  return sequence_number > ack_frame.largest_observed ||
      ContainsKey(ack_frame.missing_packets, sequence_number);
}

void InsertMissingPacketsBetween(QuicAckFrame* ack_frame,
                                 QuicPacketSequenceNumber lower,
                                 QuicPacketSequenceNumber higher) {
  for (QuicPacketSequenceNumber i = lower; i < higher; ++i) {
    ack_frame->missing_packets.insert(i);
  }
}

QuicStopWaitingFrame::QuicStopWaitingFrame()
    : entropy_hash(0),
      least_unacked(0) {
}

QuicStopWaitingFrame::~QuicStopWaitingFrame() {}

QuicAckFrame::QuicAckFrame()
    : entropy_hash(0),
      largest_observed(0),
      delta_time_largest_observed(QuicTime::Delta::Infinite()),
      is_truncated(false) {}

QuicAckFrame::~QuicAckFrame() {}

QuicRstStreamErrorCode AdjustErrorForVersion(
    QuicRstStreamErrorCode error_code,
    QuicVersion version) {
  return error_code;
}

QuicRstStreamFrame::QuicRstStreamFrame()
    : stream_id(0),
      error_code(QUIC_STREAM_NO_ERROR) {
}

QuicRstStreamFrame::QuicRstStreamFrame(QuicStreamId stream_id,
                                       QuicRstStreamErrorCode error_code,
                                       QuicStreamOffset bytes_written)
    : stream_id(stream_id),
      error_code(error_code),
      byte_offset(bytes_written) {
  DCHECK_LE(error_code, numeric_limits<uint8>::max());
}

QuicConnectionCloseFrame::QuicConnectionCloseFrame()
    : error_code(QUIC_NO_ERROR) {
}

QuicFrame::QuicFrame() {}

QuicFrame::QuicFrame(QuicPaddingFrame* padding_frame)
    : type(PADDING_FRAME),
      padding_frame(padding_frame) {
}

QuicFrame::QuicFrame(QuicStreamFrame* stream_frame)
    : type(STREAM_FRAME),
      stream_frame(stream_frame) {
}

QuicFrame::QuicFrame(QuicAckFrame* frame)
    : type(ACK_FRAME),
      ack_frame(frame) {
}

QuicFrame::QuicFrame(QuicStopWaitingFrame* frame)
    : type(STOP_WAITING_FRAME),
      stop_waiting_frame(frame) {
}

QuicFrame::QuicFrame(QuicPingFrame* frame)
    : type(PING_FRAME),
      ping_frame(frame) {
}

QuicFrame::QuicFrame(QuicRstStreamFrame* frame)
    : type(RST_STREAM_FRAME),
      rst_stream_frame(frame) {
}

QuicFrame::QuicFrame(QuicConnectionCloseFrame* frame)
    : type(CONNECTION_CLOSE_FRAME),
      connection_close_frame(frame) {
}

QuicFrame::QuicFrame(QuicGoAwayFrame* frame)
    : type(GOAWAY_FRAME),
      goaway_frame(frame) {
}

QuicFrame::QuicFrame(QuicWindowUpdateFrame* frame)
    : type(WINDOW_UPDATE_FRAME),
      window_update_frame(frame) {
}

QuicFrame::QuicFrame(QuicBlockedFrame* frame)
    : type(BLOCKED_FRAME),
      blocked_frame(frame) {
}

QuicFecData::QuicFecData() : fec_group(0) {}

ostream& operator<<(ostream& os, const QuicStopWaitingFrame& sent_info) {
  os << "entropy_hash: " << static_cast<int>(sent_info.entropy_hash)
     << " least_unacked: " << sent_info.least_unacked;
  return os;
}

ostream& operator<<(ostream& os, const QuicAckFrame& ack_frame) {
  os << "entropy_hash: " << static_cast<int>(ack_frame.entropy_hash)
     << " largest_observed: " << ack_frame.largest_observed
     << " delta_time_largest_observed: "
     << ack_frame.delta_time_largest_observed.ToMicroseconds()
     << " missing_packets: [ ";
  for (SequenceNumberSet::const_iterator it = ack_frame.missing_packets.begin();
       it != ack_frame.missing_packets.end(); ++it) {
    os << *it << " ";
  }
  os << " ] is_truncated: " << ack_frame.is_truncated;
  os << " revived_packets: [ ";
  for (SequenceNumberSet::const_iterator it = ack_frame.revived_packets.begin();
       it != ack_frame.revived_packets.end(); ++it) {
    os << *it << " ";
  }
  os << " ] received_packets: [ ";
  for (PacketTimeList::const_iterator it =
           ack_frame.received_packet_times.begin();
           it != ack_frame.received_packet_times.end(); ++it) {
    os << it->first << " at " << it->second.ToDebuggingValue() << " ";
  }
  os << " ]";
  return os;
}

ostream& operator<<(ostream& os, const QuicFrame& frame) {
  switch (frame.type) {
  case PADDING_FRAME: {
      os << "type { PADDING_FRAME } ";
      break;
    }
    case RST_STREAM_FRAME: {
      os << "type { " << RST_STREAM_FRAME << " } " << *(frame.rst_stream_frame);
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
    default: {
      LOG(ERROR) << "Unknown frame type: " << frame.type;
      break;
    }
  }
  return os;
}

ostream& operator<<(ostream& os, const QuicRstStreamFrame& rst_frame) {
  os << "stream_id { " << rst_frame.stream_id << " } "
     << "error_code { " << rst_frame.error_code << " } "
     << "error_details { " << rst_frame.error_details << " }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicConnectionCloseFrame& connection_close_frame) {
  os << "error_code { " << connection_close_frame.error_code << " } "
     << "error_details { " << connection_close_frame.error_details << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicGoAwayFrame& goaway_frame) {
  os << "error_code { " << goaway_frame.error_code << " } "
     << "last_good_stream_id { " << goaway_frame.last_good_stream_id << " } "
     << "reason_phrase { " << goaway_frame.reason_phrase << " }\n";
  return os;
}

ostream& operator<<(ostream& os,
                    const QuicWindowUpdateFrame& window_update_frame) {
  os << "stream_id { " << window_update_frame.stream_id << " } "
     << "byte_offset { " << window_update_frame.byte_offset << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicBlockedFrame& blocked_frame) {
  os << "stream_id { " << blocked_frame.stream_id << " }\n";
  return os;
}

ostream& operator<<(ostream& os, const QuicStreamFrame& stream_frame) {
  os << "stream_id { " << stream_frame.stream_id << " } "
     << "fin { " << stream_frame.fin << " } "
     << "offset { " << stream_frame.offset << " } "
     << "data { "
     << QuicUtils::StringToHexASCIIDump(*(stream_frame.GetDataAsString()))
     << " }\n";
  return os;
}

QuicGoAwayFrame::QuicGoAwayFrame()
    : error_code(QUIC_NO_ERROR),
      last_good_stream_id(0) {
}

QuicGoAwayFrame::QuicGoAwayFrame(QuicErrorCode error_code,
                                 QuicStreamId last_good_stream_id,
                                 const string& reason)
    : error_code(error_code),
      last_good_stream_id(last_good_stream_id),
      reason_phrase(reason) {
  DCHECK_LE(error_code, numeric_limits<uint8>::max());
}

QuicData::QuicData(const char* buffer,
                   size_t length)
    : buffer_(buffer),
      length_(length),
      owns_buffer_(false) {
}

QuicData::QuicData(char* buffer,
                   size_t length,
                   bool owns_buffer)
    : buffer_(buffer),
      length_(length),
      owns_buffer_(owns_buffer) {
}

QuicData::~QuicData() {
  if (owns_buffer_) {
    delete [] const_cast<char*>(buffer_);
  }
}

QuicWindowUpdateFrame::QuicWindowUpdateFrame(QuicStreamId stream_id,
                                             QuicStreamOffset byte_offset)
    : stream_id(stream_id),
      byte_offset(byte_offset) {}

QuicBlockedFrame::QuicBlockedFrame(QuicStreamId stream_id)
    : stream_id(stream_id) {}

QuicPacket::QuicPacket(char* buffer,
                       size_t length,
                       bool owns_buffer,
                       QuicConnectionIdLength connection_id_length,
                       bool includes_version,
                       QuicSequenceNumberLength sequence_number_length)
    : QuicData(buffer, length, owns_buffer),
      buffer_(buffer),
      connection_id_length_(connection_id_length),
      includes_version_(includes_version),
      sequence_number_length_(sequence_number_length) {
}

QuicEncryptedPacket::QuicEncryptedPacket(const char* buffer,
                                         size_t length)
    : QuicData(buffer, length) {
}

QuicEncryptedPacket::QuicEncryptedPacket(char* buffer,
                                         size_t length,
                                         bool owns_buffer)
      : QuicData(buffer, length, owns_buffer) {
}

StringPiece QuicPacket::FecProtectedData() const {
  const size_t start_of_fec = GetStartOfFecProtectedData(
      connection_id_length_, includes_version_, sequence_number_length_);
  return StringPiece(data() + start_of_fec, length() - start_of_fec);
}

StringPiece QuicPacket::AssociatedData() const {
  return StringPiece(
      data() + kStartOfHashData,
      GetStartOfEncryptedData(
          connection_id_length_, includes_version_, sequence_number_length_) -
      kStartOfHashData);
}

StringPiece QuicPacket::BeforePlaintext() const {
  return StringPiece(data(), GetStartOfEncryptedData(connection_id_length_,
                                                     includes_version_,
                                                     sequence_number_length_));
}

StringPiece QuicPacket::Plaintext() const {
  const size_t start_of_encrypted_data =
      GetStartOfEncryptedData(
          connection_id_length_, includes_version_, sequence_number_length_);
  return StringPiece(data() + start_of_encrypted_data,
                     length() - start_of_encrypted_data);
}

RetransmittableFrames::RetransmittableFrames(EncryptionLevel level)
    : encryption_level_(level), has_crypto_handshake_(NOT_HANDSHAKE) {
}

RetransmittableFrames::~RetransmittableFrames() {
  for (QuicFrames::iterator it = frames_.begin(); it != frames_.end(); ++it) {
    switch (it->type) {
      case PADDING_FRAME:
        delete it->padding_frame;
        break;
      case STREAM_FRAME:
        delete it->stream_frame;
        break;
      case ACK_FRAME:
        delete it->ack_frame;
        break;
      case STOP_WAITING_FRAME:
        delete it->stop_waiting_frame;
        break;
      case PING_FRAME:
        delete it->ping_frame;
        break;
      case RST_STREAM_FRAME:
        delete it->rst_stream_frame;
        break;
      case CONNECTION_CLOSE_FRAME:
        delete it->connection_close_frame;
        break;
      case GOAWAY_FRAME:
        delete it->goaway_frame;
        break;
      case WINDOW_UPDATE_FRAME:
        delete it->window_update_frame;
        break;
      case BLOCKED_FRAME:
        delete it->blocked_frame;
        break;
      case NUM_FRAME_TYPES:
        DCHECK(false) << "Cannot delete type: " << it->type;
    }
  }
  STLDeleteElements(&stream_data_);
}

const QuicFrame& RetransmittableFrames::AddStreamFrame(
    QuicStreamFrame* stream_frame) {
  // Make an owned copy of the stream frame's data.
  stream_data_.push_back(stream_frame->GetDataAsString());
  // Ensure the stream frame's IOVector points to the owned copy of the data.
  stream_frame->data.Clear();
  stream_frame->data.Append(const_cast<char*>(stream_data_.back()->data()),
                            stream_data_.back()->size());
  frames_.push_back(QuicFrame(stream_frame));
  if (stream_frame->stream_id == kCryptoStreamId) {
    has_crypto_handshake_ = IS_HANDSHAKE;
  }
  return frames_.back();
}

const QuicFrame& RetransmittableFrames::AddNonStreamFrame(
    const QuicFrame& frame) {
  DCHECK_NE(frame.type, STREAM_FRAME);
  frames_.push_back(frame);
  return frames_.back();
}

SerializedPacket::SerializedPacket(
    QuicPacketSequenceNumber sequence_number,
    QuicSequenceNumberLength sequence_number_length,
    QuicEncryptedPacket* packet,
    QuicPacketEntropyHash entropy_hash,
    RetransmittableFrames* retransmittable_frames)
    : sequence_number(sequence_number),
      sequence_number_length(sequence_number_length),
      packet(packet),
      entropy_hash(entropy_hash),
      retransmittable_frames(retransmittable_frames),
      is_fec_packet(false) {
}

SerializedPacket::~SerializedPacket() {}

QuicEncryptedPacket* QuicEncryptedPacket::Clone() const {
  char* buffer = new char[this->length()];
  memcpy(buffer, this->data(), this->length());
  return new QuicEncryptedPacket(buffer, this->length(), true);
}

ostream& operator<<(ostream& os, const QuicEncryptedPacket& s) {
  os << s.length() << "-byte data";
  return os;
}

TransmissionInfo::TransmissionInfo()
    : retransmittable_frames(nullptr),
      sequence_number_length(PACKET_1BYTE_SEQUENCE_NUMBER),
      sent_time(QuicTime::Zero()),
      bytes_sent(0),
      nack_count(0),
      transmission_type(NOT_RETRANSMISSION),
      all_transmissions(nullptr),
      in_flight(false),
      is_unackable(false),
      is_fec_packet(false) {
}

TransmissionInfo::TransmissionInfo(
    RetransmittableFrames* retransmittable_frames,
    QuicSequenceNumberLength sequence_number_length,
    TransmissionType transmission_type,
    QuicTime sent_time,
    QuicByteCount bytes_sent,
    bool is_fec_packet)
    : retransmittable_frames(retransmittable_frames),
      sequence_number_length(sequence_number_length),
      sent_time(sent_time),
      bytes_sent(bytes_sent),
      nack_count(0),
      transmission_type(transmission_type),
      all_transmissions(nullptr),
      in_flight(false),
      is_unackable(false),
      is_fec_packet(is_fec_packet) {
}

}  // namespace net
