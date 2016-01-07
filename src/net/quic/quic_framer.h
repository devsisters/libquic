// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FRAMER_H_
#define NET_QUIC_QUIC_FRAMER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace test {
class QuicFramerPeer;
}  // namespace test

class QuicDataReader;
class QuicDataWriter;
class QuicDecrypter;
class QuicEncrypter;
class QuicFramer;

// Number of bytes reserved for the frame type preceding each frame.
const size_t kQuicFrameTypeSize = 1;
// Number of bytes reserved for error code.
const size_t kQuicErrorCodeSize = 4;
// Number of bytes reserved to denote the length of error details field.
const size_t kQuicErrorDetailsLengthSize = 2;

// Maximum number of bytes reserved for stream id.
const size_t kQuicMaxStreamIdSize = 4;
// Maximum number of bytes reserved for byte offset in stream frame.
const size_t kQuicMaxStreamOffsetSize = 8;
// Number of bytes reserved to store payload length in stream frame.
const size_t kQuicStreamPayloadLengthSize = 2;

// Size in bytes of the entropy hash sent in ack frames.
const size_t kQuicEntropyHashSize = 1;
// Size in bytes reserved for the delta time of the largest observed
// packet number in ack frames.
const size_t kQuicDeltaTimeLargestObservedSize = 2;
// Size in bytes reserved for the number of received packets with timestamps.
const size_t kQuicNumTimestampsSize = 1;
// Size in bytes reserved for the number of missing packets in ack frames.
const size_t kNumberOfNackRangesSize = 1;
// Maximum number of missing packet ranges that can fit within an ack frame.
const size_t kMaxNackRanges = (1 << (kNumberOfNackRangesSize * 8)) - 1;
// Size in bytes reserved for the number of revived packets in ack frames.
const size_t kNumberOfRevivedPacketsSize = 1;
// Maximum number of revived packets that can fit within an ack frame.
const size_t kMaxRevivedPackets = (1 << (kNumberOfRevivedPacketsSize * 8)) - 1;

// This class receives callbacks from the framer when packets
// are processed.
class NET_EXPORT_PRIVATE QuicFramerVisitorInterface {
 public:
  virtual ~QuicFramerVisitorInterface() {}

  // Called if an error is detected in the QUIC protocol.
  virtual void OnError(QuicFramer* framer) = 0;

  // Called only when |perspective_| is IS_SERVER and the the framer gets a
  // packet with version flag true and the version on the packet doesn't match
  // |quic_version_|. The visitor should return true after it updates the
  // version of the |framer_| to |received_version| or false to stop processing
  // this packet.
  virtual bool OnProtocolVersionMismatch(QuicVersion received_version) = 0;

  // Called when a new packet has been received, before it
  // has been validated or processed.
  virtual void OnPacket() = 0;

  // Called when a public reset packet has been parsed but has not yet
  // been validated.
  virtual void OnPublicResetPacket(const QuicPublicResetPacket& packet) = 0;

  // Called only when |perspective_| is IS_CLIENT and a version negotiation
  // packet has been parsed.
  virtual void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& packet) = 0;

  // Called when a lost packet has been recovered via FEC,
  // before it has been processed.
  virtual void OnRevivedPacket() = 0;

  // Called when the public header has been parsed, but has not been
  // authenticated. If it returns false, framing for this packet will cease.
  virtual bool OnUnauthenticatedPublicHeader(
      const QuicPacketPublicHeader& header) = 0;

  // Called when the unauthenticated portion of the header has been parsed.
  // If OnUnauthenticatedHeader returns false, framing for this packet will
  // cease.
  virtual bool OnUnauthenticatedHeader(const QuicPacketHeader& header) = 0;

  // Called when a packet has been decrypted. |level| is the encryption level
  // of the packet.
  virtual void OnDecryptedPacket(EncryptionLevel level) = 0;

  // Called when the complete header of a packet had been parsed.
  // If OnPacketHeader returns false, framing for this packet will cease.
  virtual bool OnPacketHeader(const QuicPacketHeader& header) = 0;

  // Called when a data packet is parsed that is part of an FEC group.
  // |payload| is the non-encrypted FEC protected payload of the packet.
  virtual void OnFecProtectedPayload(base::StringPiece payload) = 0;

  // Called when a StreamFrame has been parsed.
  virtual bool OnStreamFrame(const QuicStreamFrame& frame) = 0;

  // Called when a AckFrame has been parsed.  If OnAckFrame returns false,
  // the framer will stop parsing the current packet.
  virtual bool OnAckFrame(const QuicAckFrame& frame) = 0;

  // Called when a StopWaitingFrame has been parsed.
  virtual bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) = 0;

  // Called when a PingFrame has been parsed.
  virtual bool OnPingFrame(const QuicPingFrame& frame) = 0;

  // Called when a RstStreamFrame has been parsed.
  virtual bool OnRstStreamFrame(const QuicRstStreamFrame& frame) = 0;

  // Called when a ConnectionCloseFrame has been parsed.
  virtual bool OnConnectionCloseFrame(
      const QuicConnectionCloseFrame& frame) = 0;

  // Called when a GoAwayFrame has been parsed.
  virtual bool OnGoAwayFrame(const QuicGoAwayFrame& frame) = 0;

  // Called when a WindowUpdateFrame has been parsed.
  virtual bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) = 0;

  // Called when a BlockedFrame has been parsed.
  virtual bool OnBlockedFrame(const QuicBlockedFrame& frame) = 0;

  // Called when FEC data has been parsed.
  virtual void OnFecData(base::StringPiece redundancy) = 0;

  // Called when a packet has been completely processed.
  virtual void OnPacketComplete() = 0;
};

// This class calculates the received entropy of the ack packet being
// framed, should it get truncated.
class NET_EXPORT_PRIVATE QuicReceivedEntropyHashCalculatorInterface {
 public:
  virtual ~QuicReceivedEntropyHashCalculatorInterface() {}

  // When an ack frame gets truncated while being framed the received
  // entropy of the ack frame needs to be calculated since the some of the
  // missing packets are not added and the largest observed might be lowered.
  // This should return the received entropy hash of the packets received up to
  // and including |packet_number|.
  virtual QuicPacketEntropyHash EntropyHash(
      QuicPacketNumber packet_number) const = 0;
};

// Class for parsing and constructing QUIC packets.  It has a
// QuicFramerVisitorInterface that is called when packets are parsed.
// It also has a QuicFecBuilder that is called when packets are constructed
// in order to generate FEC data for subsequently building FEC packets.
class NET_EXPORT_PRIVATE QuicFramer {
 public:
  // Constructs a new framer that installs a kNULL QuicEncrypter and
  // QuicDecrypter for level ENCRYPTION_NONE. |supported_versions| specifies the
  // list of supported QUIC versions. |quic_version_| is set to the maximum
  // version in |supported_versions|.
  QuicFramer(const QuicVersionVector& supported_versions,
             QuicTime creation_time,
             Perspective perspective);

  virtual ~QuicFramer();

  // Returns true if |version| is a supported protocol version.
  bool IsSupportedVersion(const QuicVersion version) const;

  // Set callbacks to be called from the framer.  A visitor must be set, or
  // else the framer will likely crash.  It is acceptable for the visitor
  // to do nothing.  If this is called multiple times, only the last visitor
  // will be used.
  void set_visitor(QuicFramerVisitorInterface* visitor) { visitor_ = visitor; }

  const QuicVersionVector& supported_versions() const {
    return supported_versions_;
  }

  QuicVersion version() const { return quic_version_; }

  void set_version(const QuicVersion version);

  // Does not DCHECK for supported version. Used by tests to set unsupported
  // version to trigger version negotiation.
  void set_version_for_tests(const QuicVersion version) {
    quic_version_ = version;
  }

  // Set entropy calculator to be called from the framer when it needs the
  // entropy of a truncated ack frame. An entropy calculator must be set or else
  // the framer will likely crash. If this is called multiple times, only the
  // last calculator will be used.
  void set_received_entropy_calculator(
      QuicReceivedEntropyHashCalculatorInterface* entropy_calculator) {
    entropy_calculator_ = entropy_calculator;
  }

  QuicErrorCode error() const { return error_; }

  // Pass a UDP packet into the framer for parsing.
  // Return true if the packet was processed succesfully. |packet| must be a
  // single, complete UDP packet (not a frame of a packet).  This packet
  // might be null padded past the end of the payload, which will be correctly
  // ignored.
  bool ProcessPacket(const QuicEncryptedPacket& packet);

  // Pass a data packet that was revived from FEC data into the framer
  // for parsing.
  // Return true if the packet was processed succesfully. |payload| must be
  // the complete DECRYPTED payload of the revived packet.
  bool ProcessRevivedPacket(QuicPacketHeader* header,
                            base::StringPiece payload);

  // Largest size in bytes of all stream frame fields without the payload.
  static size_t GetMinStreamFrameSize(QuicStreamId stream_id,
                                      QuicStreamOffset offset,
                                      bool last_frame_in_packet,
                                      InFecGroup is_in_fec_group);
  // Size in bytes of all ack frame fields without the missing packets.
  static size_t GetMinAckFrameSize(
      QuicPacketNumberLength largest_observed_length);
  // Size in bytes of a stop waiting frame.
  static size_t GetStopWaitingFrameSize(
      QuicPacketNumberLength packet_number_length);
  // Size in bytes of all reset stream frame without the error details.
  // Used before QUIC_VERSION_25.
  static size_t GetMinRstStreamFrameSize();
  // Size in bytes of all reset stream frame fields.
  static size_t GetRstStreamFrameSize();
  // Size in bytes of all connection close frame fields without the error
  // details and the missing packets from the enclosed ack frame.
  static size_t GetMinConnectionCloseFrameSize();
  // Size in bytes of all GoAway frame fields without the reason phrase.
  static size_t GetMinGoAwayFrameSize();
  // Size in bytes of all WindowUpdate frame fields.
  static size_t GetWindowUpdateFrameSize();
  // Size in bytes of all Blocked frame fields.
  static size_t GetBlockedFrameSize();
  // Size in bytes required to serialize the stream id.
  static size_t GetStreamIdSize(QuicStreamId stream_id);
  // Size in bytes required to serialize the stream offset.
  static size_t GetStreamOffsetSize(QuicStreamOffset offset);
  // Size in bytes required for a serialized version negotiation packet
  static size_t GetVersionNegotiationPacketSize(size_t number_versions);

  // Returns the number of bytes added to the packet for the specified frame,
  // and 0 if the frame doesn't fit.  Includes the header size for the first
  // frame.
  size_t GetSerializedFrameLength(const QuicFrame& frame,
                                  size_t free_bytes,
                                  bool first_frame_in_packet,
                                  bool last_frame_in_packet,
                                  InFecGroup is_in_fec_group,
                                  QuicPacketNumberLength packet_number_length);

  // Returns the associated data from the encrypted packet |encrypted| as a
  // stringpiece.
  static base::StringPiece GetAssociatedDataFromEncryptedPacket(
      const QuicEncryptedPacket& encrypted,
      QuicConnectionIdLength connection_id_length,
      bool includes_version,
      QuicPacketNumberLength packet_number_length);

  // Serializes a packet containing |frames| into |buffer|.
  // Returns the length of the packet, which must not be longer than
  // |packet_length|.  Returns 0 if it fails to serialize.
  size_t BuildDataPacket(const QuicPacketHeader& header,
                         const QuicFrames& frames,
                         char* buffer,
                         size_t packet_length);

  // Returns a QuicPacket* that is owned by the caller, and is populated with
  // the fields in |header| and |fec|.  Returns nullptr if the packet could
  // not be created.
  QuicPacket* BuildFecPacket(const QuicPacketHeader& header,
                             base::StringPiece redundancy);

  // Returns a new public reset packet, owned by the caller.
  static QuicEncryptedPacket* BuildPublicResetPacket(
      const QuicPublicResetPacket& packet);

  // Returns a new version negotiation packet, owned by the caller.
  static QuicEncryptedPacket* BuildVersionNegotiationPacket(
      QuicConnectionId connection_id,
      const QuicVersionVector& versions);

  // SetDecrypter sets the primary decrypter, replacing any that already exists,
  // and takes ownership. If an alternative decrypter is in place then the
  // function DCHECKs. This is intended for cases where one knows that future
  // packets will be using the new decrypter and the previous decrypter is now
  // obsolete. |level| indicates the encryption level of the new decrypter.
  void SetDecrypter(EncryptionLevel level, QuicDecrypter* decrypter);

  // SetAlternativeDecrypter sets a decrypter that may be used to decrypt
  // future packets and takes ownership of it. |level| indicates the encryption
  // level of the decrypter. If |latch_once_used| is true, then the first time
  // that the decrypter is successful it will replace the primary decrypter.
  // Otherwise both decrypters will remain active and the primary decrypter
  // will be the one last used.
  void SetAlternativeDecrypter(EncryptionLevel level,
                               QuicDecrypter* decrypter,
                               bool latch_once_used);

  const QuicDecrypter* decrypter() const;
  const QuicDecrypter* alternative_decrypter() const;

  // Changes the encrypter used for level |level| to |encrypter|. The function
  // takes ownership of |encrypter|.
  void SetEncrypter(EncryptionLevel level, QuicEncrypter* encrypter);

  // Returns the length of the data encrypted into |buffer| if |buffer_len| is
  // long enough, and otherwise 0.
  size_t EncryptPayload(EncryptionLevel level,
                        QuicPacketNumber packet_number,
                        const QuicPacket& packet,
                        char* buffer,
                        size_t buffer_len);

  // Returns the maximum length of plaintext that can be encrypted
  // to ciphertext no larger than |ciphertext_size|.
  size_t GetMaxPlaintextSize(size_t ciphertext_size);

  const std::string& detailed_error() { return detailed_error_; }

  // The minimum packet number length required to represent |packet_number|.
  static QuicPacketNumberLength GetMinSequenceNumberLength(
      QuicPacketNumber packet_number);

  void SetSupportedVersions(const QuicVersionVector& versions) {
    supported_versions_ = versions;
    quic_version_ = versions[0];
  }

  void set_validate_flags(bool value) { validate_flags_ = value; }

  Perspective perspective() const { return perspective_; }

  static QuicPacketEntropyHash GetPacketEntropyHash(
      const QuicPacketHeader& header);

  // Called when a PATH_CLOSED frame has been sent/received on |path_id|.
  void OnPathClosed(QuicPathId path_id);

 private:
  friend class test::QuicFramerPeer;

  typedef std::map<QuicPacketNumber, uint8_t> NackRangeMap;

  struct AckFrameInfo {
    AckFrameInfo();
    ~AckFrameInfo();

    // The maximum delta between ranges.
    QuicPacketNumber max_delta;
    // Nack ranges starting with start packet numbers and lengths.
    NackRangeMap nack_ranges;
  };

  bool ProcessDataPacket(QuicDataReader* reader,
                         const QuicPacketPublicHeader& public_header,
                         const QuicEncryptedPacket& packet,
                         char* decrypted_buffer,
                         size_t buffer_length);

  bool ProcessPublicResetPacket(QuicDataReader* reader,
                                const QuicPacketPublicHeader& public_header);

  bool ProcessVersionNegotiationPacket(QuicDataReader* reader,
                                       QuicPacketPublicHeader* public_header);

  bool ProcessPublicHeader(QuicDataReader* reader,
                           QuicPacketPublicHeader* header);

  // Processes the unauthenticated portion of the header into |header| from
  // the current QuicDataReader.  Returns true on success, false on failure.
  bool ProcessUnauthenticatedHeader(QuicDataReader* encrypted_reader,
                                    QuicPacketHeader* header);

  // Processes the authenticated portion of the header into |header| from
  // the current QuicDataReader.  Returns true on success, false on failure.
  bool ProcessAuthenticatedHeader(QuicDataReader* reader,
                                  QuicPacketHeader* header);

  bool ProcessPathId(QuicDataReader* reader, QuicPathId* path_id);
  bool ProcessPacketSequenceNumber(QuicDataReader* reader,
                                   QuicPacketNumberLength packet_number_length,
                                   QuicPacketNumber last_packet_number,
                                   QuicPacketNumber* packet_number);
  bool ProcessFrameData(QuicDataReader* reader, const QuicPacketHeader& header);
  bool ProcessStreamFrame(QuicDataReader* reader,
                          uint8_t frame_type,
                          QuicStreamFrame* frame);
  bool ProcessAckFrame(QuicDataReader* reader,
                       uint8_t frame_type,
                       QuicAckFrame* frame);
  bool ProcessTimestampsInAckFrame(QuicDataReader* reader, QuicAckFrame* frame);
  bool ProcessStopWaitingFrame(QuicDataReader* reader,
                               const QuicPacketHeader& public_header,
                               QuicStopWaitingFrame* stop_waiting);
  bool ProcessRstStreamFrame(QuicDataReader* reader, QuicRstStreamFrame* frame);
  bool ProcessConnectionCloseFrame(QuicDataReader* reader,
                                   QuicConnectionCloseFrame* frame);
  bool ProcessGoAwayFrame(QuicDataReader* reader, QuicGoAwayFrame* frame);
  bool ProcessWindowUpdateFrame(QuicDataReader* reader,
                                QuicWindowUpdateFrame* frame);
  bool ProcessBlockedFrame(QuicDataReader* reader, QuicBlockedFrame* frame);

  bool DecryptPayload(QuicDataReader* encrypted_reader,
                      const QuicPacketHeader& header,
                      const QuicEncryptedPacket& packet,
                      char* decrypted_buffer,
                      size_t buffer_length,
                      size_t* decrypted_length);

  // Checks if |path_id| is a viable path to receive packets on. Returns true
  // and sets |last_packet_number| if the path is not closed. Returns false
  // otherwise.
  bool IsValidPath(QuicPathId path_id, QuicPacketNumber* last_packet_number);

  // Returns the full packet number from the truncated
  // wire format version and the last seen packet number.
  QuicPacketNumber CalculatePacketNumberFromWire(
      QuicPacketNumberLength packet_number_length,
      QuicPacketNumber last_packet_number,
      QuicPacketNumber packet_number) const;

  // Returns the QuicTime::Delta corresponding to the time from when the framer
  // was created.
  const QuicTime::Delta CalculateTimestampFromWire(uint32_t time_delta_us);

  // Computes the wire size in bytes of the |ack| frame, assuming no truncation.
  size_t GetAckFrameSize(const QuicAckFrame& ack,
                         QuicPacketNumberLength packet_number_length);

  // Computes the wire size in bytes of the payload of |frame|.
  size_t ComputeFrameLength(const QuicFrame& frame,
                            bool last_frame_in_packet,
                            InFecGroup is_in_fec_group,
                            QuicPacketNumberLength packet_number_length);

  static bool AppendPacketSequenceNumber(
      QuicPacketNumberLength packet_number_length,
      QuicPacketNumber packet_number,
      QuicDataWriter* writer);

  static uint8_t GetSequenceNumberFlags(
      QuicPacketNumberLength packet_number_length);

  static AckFrameInfo GetAckFrameInfo(const QuicAckFrame& frame);

  // The Append* methods attempt to write the provided header or frame using the
  // |writer|, and return true if successful.

  // If header.public_header.version_flag is set, the version in the
  // packet will be set -- but it will be set from quic_version_ not
  // header.public_header.versions.
  bool AppendPacketHeader(const QuicPacketHeader& header,
                          QuicDataWriter* writer);
  bool AppendTypeByte(const QuicFrame& frame,
                      bool last_frame_in_packet,
                      QuicDataWriter* writer);
  bool AppendStreamFrame(const QuicStreamFrame& frame,
                         bool last_frame_in_packet,
                         QuicDataWriter* builder);
  bool AppendAckFrameAndTypeByte(const QuicPacketHeader& header,
                                 const QuicAckFrame& frame,
                                 QuicDataWriter* builder);
  bool AppendTimestampToAckFrame(const QuicAckFrame& frame,
                                 QuicDataWriter* builder);
  bool AppendStopWaitingFrame(const QuicPacketHeader& header,
                              const QuicStopWaitingFrame& frame,
                              QuicDataWriter* builder);
  bool AppendRstStreamFrame(const QuicRstStreamFrame& frame,
                            QuicDataWriter* builder);
  bool AppendConnectionCloseFrame(const QuicConnectionCloseFrame& frame,
                                  QuicDataWriter* builder);
  bool AppendGoAwayFrame(const QuicGoAwayFrame& frame, QuicDataWriter* writer);
  bool AppendWindowUpdateFrame(const QuicWindowUpdateFrame& frame,
                               QuicDataWriter* writer);
  bool AppendBlockedFrame(const QuicBlockedFrame& frame,
                          QuicDataWriter* writer);

  bool RaiseError(QuicErrorCode error);

  void set_error(QuicErrorCode error) { error_ = error; }

  void set_detailed_error(const char* error) { detailed_error_ = error; }

  std::string detailed_error_;
  QuicFramerVisitorInterface* visitor_;
  QuicReceivedEntropyHashCalculatorInterface* entropy_calculator_;
  QuicErrorCode error_;
  // Set of closed paths. A path is considered as closed if a PATH_CLOSED frame
  // has been sent/received.
  // TODO(fayang): this set is never cleaned up. A possible improvement is to
  // use intervals.
  base::hash_set<QuicPathId> closed_paths_;
  // Map mapping path id to packet number of last successfully decrypted/revived
  // received packet.
  base::hash_map<QuicPathId, QuicPacketNumber> last_packet_numbers_;
  // Updated by ProcessPacketHeader when it succeeds.
  QuicPacketNumber last_packet_number_;
  // The path on which last successfully decrypted/revived packet was received.
  QuicPathId last_path_id_;
  // Updated by WritePacketHeader.
  QuicConnectionId last_serialized_connection_id_;
  // Version of the protocol being used.
  QuicVersion quic_version_;
  // This vector contains QUIC versions which we currently support.
  // This should be ordered such that the highest supported version is the first
  // element, with subsequent elements in descending order (versions can be
  // skipped as necessary).
  QuicVersionVector supported_versions_;
  // Primary decrypter used to decrypt packets during parsing.
  scoped_ptr<QuicDecrypter> decrypter_;
  // Alternative decrypter that can also be used to decrypt packets.
  scoped_ptr<QuicDecrypter> alternative_decrypter_;
  // The encryption level of |decrypter_|.
  EncryptionLevel decrypter_level_;
  // The encryption level of |alternative_decrypter_|.
  EncryptionLevel alternative_decrypter_level_;
  // |alternative_decrypter_latch_| is true if, when |alternative_decrypter_|
  // successfully decrypts a packet, we should install it as the only
  // decrypter.
  bool alternative_decrypter_latch_;
  // Encrypters used to encrypt packets via EncryptPayload().
  scoped_ptr<QuicEncrypter> encrypter_[NUM_ENCRYPTION_LEVELS];
  // Tracks if the framer is being used by the entity that received the
  // connection or the entity that initiated it.
  Perspective perspective_;
  // If false, skip validation that the public flags are set to legal values.
  bool validate_flags_;
  // The time this framer was created.  Time written to the wire will be
  // written as a delta from this value.
  QuicTime creation_time_;
  // The time delta computed for the last timestamp frame. This is relative to
  // the creation_time.
  QuicTime::Delta last_timestamp_;

  DISALLOW_COPY_AND_ASSIGN(QuicFramer);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FRAMER_H_
