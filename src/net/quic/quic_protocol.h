// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_PROTOCOL_H_
#define NET_QUIC_QUIC_PROTOCOL_H_

#include <stddef.h>
#include <limits>
#include <list>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/basictypes.h"
#include "base/containers/hash_tables.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/iovector.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_time.h"

namespace net {

class QuicAckNotifier;
class QuicPacket;
struct QuicPacketHeader;

typedef uint64 QuicConnectionId;
typedef uint32 QuicStreamId;
typedef uint64 QuicStreamOffset;
typedef uint64 QuicPacketSequenceNumber;
typedef QuicPacketSequenceNumber QuicFecGroupNumber;
typedef uint64 QuicPublicResetNonceProof;
typedef uint8 QuicPacketEntropyHash;
typedef uint32 QuicHeaderId;
// QuicTag is the type of a tag in the wire protocol.
typedef uint32 QuicTag;
typedef std::vector<QuicTag> QuicTagVector;
typedef std::map<QuicTag, std::string> QuicTagValueMap;
// TODO(rtenneti): Didn't use SpdyPriority because SpdyPriority is uint8 and
// QuicPriority is uint32. Use SpdyPriority when we change the QUIC_VERSION.
typedef uint32 QuicPriority;

// Default and initial maximum size in bytes of a QUIC packet.
const QuicByteCount kDefaultMaxPacketSize = 1350;
// Default initial maximum size in bytes of a QUIC packet for servers.
const QuicByteCount kDefaultServerMaxPacketSize = 1000;
// The maximum packet size of any QUIC packet, based on ethernet's max size,
// minus the IP and UDP headers. IPv6 has a 40 byte header, UPD adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
const QuicByteCount kMaxPacketSize = 1452;
// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
const QuicByteCount kDefaultTCPMSS = 1460;

// We match SPDY's use of 32 when secure (since we'd compete with SPDY).
const QuicPacketCount kInitialCongestionWindowSecure = 32;
// Be conservative, and just use double a typical TCP ICWND for HTTP.
const QuicPacketCount kInitialCongestionWindowInsecure = 20;

// Minimum size of initial flow control window, for both stream and session.
const uint32 kMinimumFlowControlSendWindow = 16 * 1024;  // 16 KB

// Minimum and maximum size of the CWND, in packets,
// when doing bandwidth resumption.
const QuicPacketCount kMinCongestionWindowForBandwidthResumption = 10;
const QuicPacketCount kMaxCongestionWindowForBandwidthResumption = 200;

// Maximum number of tracked packets before the connection will be closed.
// This effectively limits the max CWND to a smaller value than this.
const QuicPacketCount kMaxTrackedPackets = 5000;

// Default size of the socket receive buffer in bytes.
const QuicByteCount kDefaultSocketReceiveBuffer = 256 * 1024;
// Minimum size of the socket receive buffer in bytes.
// Smaller values are ignored.
const QuicByteCount kMinSocketReceiveBuffer = 16 * 1024;

// Don't allow a client to suggest an RTT shorter than 10ms.
const uint32 kMinInitialRoundTripTimeUs = 10 * kNumMicrosPerMilli;

// Don't allow a client to suggest an RTT longer than 15 seconds.
const uint32 kMaxInitialRoundTripTimeUs = 15 * kNumMicrosPerSecond;

// Maximum number of open streams per connection.
const size_t kDefaultMaxStreamsPerConnection = 100;

// Number of bytes reserved for public flags in the packet header.
const size_t kPublicFlagsSize = 1;
// Number of bytes reserved for version number in the packet header.
const size_t kQuicVersionSize = 4;
// Number of bytes reserved for private flags in the packet header.
const size_t kPrivateFlagsSize = 1;
// Number of bytes reserved for FEC group in the packet header.
const size_t kFecGroupSize = 1;

// Signifies that the QuicPacket will contain version of the protocol.
const bool kIncludeVersion = true;

// Index of the first byte in a QUIC packet which is used in hash calculation.
const size_t kStartOfHashData = 0;

// Limit on the delta between stream IDs.
const QuicStreamId kMaxStreamIdDelta = 200;

// Reserved ID for the crypto stream.
const QuicStreamId kCryptoStreamId = 1;

// Reserved ID for the headers stream.
const QuicStreamId kHeadersStreamId = 3;

// Maximum delayed ack time, in ms.
const int64 kMaxDelayedAckTimeMs = 25;

// The timeout before the handshake succeeds.
const int64 kInitialIdleTimeoutSecs = 5;
// The default idle timeout.
const int64 kDefaultIdleTimeoutSecs = 30;
// The maximum idle timeout that can be negotiated.
const int64 kMaximumIdleTimeoutSecs = 60 * 10;  // 10 minutes.
// The default timeout for a connection until the crypto handshake succeeds.
const int64 kMaxTimeForCryptoHandshakeSecs = 10;  // 10 secs.

// Default limit on the number of undecryptable packets the connection buffers
// before the CHLO/SHLO arrive.
const size_t kDefaultMaxUndecryptablePackets = 10;

// Default ping timeout.
const int64 kPingTimeoutSecs = 15;  // 15 secs.

// Minimum number of RTTs between Server Config Updates (SCUP) sent to client.
const int kMinIntervalBetweenServerConfigUpdatesRTTs = 10;

// Minimum time between Server Config Updates (SCUP) sent to client.
const int kMinIntervalBetweenServerConfigUpdatesMs = 1000;

// Minimum number of packets between Server Config Updates (SCUP).
const int kMinPacketsBetweenServerConfigUpdates = 100;

// The number of open streams that a server will accept is set to be slightly
// larger than the negotiated limit. Immediately closing the connection if the
// client opens slightly too many streams is not ideal: the client may have sent
// a FIN that was lost, and simultaneously opened a new stream. The number of
// streams a server accepts is a fixed increment over the negotiated limit, or a
// percentage increase, whichever is larger.
const float kMaxStreamsMultiplier = 1.1f;
const int kMaxStreamsMinimumIncrement = 10;

// We define an unsigned 16-bit floating point value, inspired by IEEE floats
// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
// bit) and denormals, but without signs, transfinites or fractions. Wire format
// 16 bits (little-endian byte order) are split into exponent (high 5) and
// mantissa (low 11) and decoded as:
//   uint64 value;
//   if (exponent == 0) value = mantissa;
//   else value = (mantissa | 1 << 11) << (exponent - 1)
const int kUFloat16ExponentBits = 5;
const int kUFloat16MaxExponent = (1 << kUFloat16ExponentBits) - 2;  // 30
const int kUFloat16MantissaBits = 16 - kUFloat16ExponentBits;  // 11
const int kUFloat16MantissaEffectiveBits = kUFloat16MantissaBits + 1;  // 12
const uint64 kUFloat16MaxValue =  // 0x3FFC0000000
    ((GG_UINT64_C(1) << kUFloat16MantissaEffectiveBits) - 1) <<
    kUFloat16MaxExponent;

enum TransmissionType {
  NOT_RETRANSMISSION,
  FIRST_TRANSMISSION_TYPE = NOT_RETRANSMISSION,
  HANDSHAKE_RETRANSMISSION,  // Retransmits due to handshake timeouts.
  ALL_UNACKED_RETRANSMISSION,  // Retransmits all unacked packets.
  ALL_INITIAL_RETRANSMISSION,  // Retransmits all initially encrypted packets.
  LOSS_RETRANSMISSION,  // Retransmits due to loss detection.
  RTO_RETRANSMISSION,  // Retransmits due to retransmit time out.
  TLP_RETRANSMISSION,  // Tail loss probes.
  LAST_TRANSMISSION_TYPE = TLP_RETRANSMISSION,
};

enum HasRetransmittableData {
  NO_RETRANSMITTABLE_DATA,
  HAS_RETRANSMITTABLE_DATA,
};

enum IsHandshake {
  NOT_HANDSHAKE,
  IS_HANDSHAKE
};

// Indicates FEC protection level for data being written.
enum FecProtection {
  MUST_FEC_PROTECT,  // Callee must FEC protect this data.
  MAY_FEC_PROTECT    // Callee does not have to but may FEC protect this data.
};

// Indicates FEC policy.
enum FecPolicy {
  FEC_PROTECT_ALWAYS,   // All data in the stream should be FEC protected.
  FEC_PROTECT_OPTIONAL  // Data in the stream does not need FEC protection.
};

enum QuicFrameType {
  // Regular frame types. The values set here cannot change without the
  // introduction of a new QUIC version.
  PADDING_FRAME = 0,
  RST_STREAM_FRAME = 1,
  CONNECTION_CLOSE_FRAME = 2,
  GOAWAY_FRAME = 3,
  WINDOW_UPDATE_FRAME = 4,
  BLOCKED_FRAME = 5,
  STOP_WAITING_FRAME = 6,
  PING_FRAME = 7,

  // STREAM and ACK frames are special frames. They are encoded differently on
  // the wire and their values do not need to be stable.
  STREAM_FRAME,
  ACK_FRAME,
  NUM_FRAME_TYPES
};

enum QuicConnectionIdLength {
  PACKET_0BYTE_CONNECTION_ID = 0,
  PACKET_1BYTE_CONNECTION_ID = 1,
  PACKET_4BYTE_CONNECTION_ID = 4,
  PACKET_8BYTE_CONNECTION_ID = 8
};

enum InFecGroup {
  NOT_IN_FEC_GROUP,
  IN_FEC_GROUP,
};

enum QuicSequenceNumberLength {
  PACKET_1BYTE_SEQUENCE_NUMBER = 1,
  PACKET_2BYTE_SEQUENCE_NUMBER = 2,
  PACKET_4BYTE_SEQUENCE_NUMBER = 4,
  PACKET_6BYTE_SEQUENCE_NUMBER = 6
};

// Used to indicate a QuicSequenceNumberLength using two flag bits.
enum QuicSequenceNumberLengthFlags {
  PACKET_FLAGS_1BYTE_SEQUENCE = 0,  // 00
  PACKET_FLAGS_2BYTE_SEQUENCE = 1,  // 01
  PACKET_FLAGS_4BYTE_SEQUENCE = 1 << 1,  // 10
  PACKET_FLAGS_6BYTE_SEQUENCE = 1 << 1 | 1,  // 11
};

// The public flags are specified in one byte.
enum QuicPacketPublicFlags {
  PACKET_PUBLIC_FLAGS_NONE = 0,

  // Bit 0: Does the packet header contains version info?
  PACKET_PUBLIC_FLAGS_VERSION = 1 << 0,

  // Bit 1: Is this packet a public reset packet?
  PACKET_PUBLIC_FLAGS_RST = 1 << 1,

  // Bits 2 and 3 specify the length of the ConnectionId as follows:
  // ----00--: 0 bytes
  // ----01--: 1 byte
  // ----10--: 4 bytes
  // ----11--: 8 bytes
  PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID = 0,
  PACKET_PUBLIC_FLAGS_1BYTE_CONNECTION_ID = 1 << 2,
  PACKET_PUBLIC_FLAGS_4BYTE_CONNECTION_ID = 1 << 3,
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID = 1 << 3 | 1 << 2,

  // Bits 4 and 5 describe the packet sequence number length as follows:
  // --00----: 1 byte
  // --01----: 2 bytes
  // --10----: 4 bytes
  // --11----: 6 bytes
  PACKET_PUBLIC_FLAGS_1BYTE_SEQUENCE = PACKET_FLAGS_1BYTE_SEQUENCE << 4,
  PACKET_PUBLIC_FLAGS_2BYTE_SEQUENCE = PACKET_FLAGS_2BYTE_SEQUENCE << 4,
  PACKET_PUBLIC_FLAGS_4BYTE_SEQUENCE = PACKET_FLAGS_4BYTE_SEQUENCE << 4,
  PACKET_PUBLIC_FLAGS_6BYTE_SEQUENCE = PACKET_FLAGS_6BYTE_SEQUENCE << 4,

  // All bits set (bits 6 and 7 are not currently used): 00111111
  PACKET_PUBLIC_FLAGS_MAX = (1 << 6) - 1
};

// The private flags are specified in one byte.
enum QuicPacketPrivateFlags {
  PACKET_PRIVATE_FLAGS_NONE = 0,

  // Bit 0: Does this packet contain an entropy bit?
  PACKET_PRIVATE_FLAGS_ENTROPY = 1 << 0,

  // Bit 1: Payload is part of an FEC group?
  PACKET_PRIVATE_FLAGS_FEC_GROUP = 1 << 1,

  // Bit 2: Payload is FEC as opposed to frames?
  PACKET_PRIVATE_FLAGS_FEC = 1 << 2,

  // All bits set (bits 3-7 are not currently used): 00000111
  PACKET_PRIVATE_FLAGS_MAX = (1 << 3) - 1
};

// The available versions of QUIC. Guaranteed that the integer value of the enum
// will match the version number.
// When adding a new version to this enum you should add it to
// kSupportedQuicVersions (if appropriate), and also add a new case to the
// helper methods QuicVersionToQuicTag, QuicTagToQuicVersion, and
// QuicVersionToString.
enum QuicVersion {
  // Special case to indicate unknown/unsupported QUIC version.
  QUIC_VERSION_UNSUPPORTED = 0,

  QUIC_VERSION_23 = 23,  // Timestamp in the ack frame.
  QUIC_VERSION_24 = 24,  // SPDY/4 header compression.
};

// This vector contains QUIC versions which we currently support.
// This should be ordered such that the highest supported version is the first
// element, with subsequent elements in descending order (versions can be
// skipped as necessary).
//
// IMPORTANT: if you are adding to this list, follow the instructions at
// http://sites/quic/adding-and-removing-versions
static const QuicVersion kSupportedQuicVersions[] = {QUIC_VERSION_24,
                                                     QUIC_VERSION_23};

typedef std::vector<QuicVersion> QuicVersionVector;

// Returns a vector of QUIC versions in kSupportedQuicVersions.
NET_EXPORT_PRIVATE QuicVersionVector QuicSupportedVersions();

// QuicTag is written to and read from the wire, but we prefer to use
// the more readable QuicVersion at other levels.
// Helper function which translates from a QuicVersion to a QuicTag. Returns 0
// if QuicVersion is unsupported.
NET_EXPORT_PRIVATE QuicTag QuicVersionToQuicTag(const QuicVersion version);

// Returns appropriate QuicVersion from a QuicTag.
// Returns QUIC_VERSION_UNSUPPORTED if version_tag cannot be understood.
NET_EXPORT_PRIVATE QuicVersion QuicTagToQuicVersion(const QuicTag version_tag);

// Helper function which translates from a QuicVersion to a string.
// Returns strings corresponding to enum names (e.g. QUIC_VERSION_6).
NET_EXPORT_PRIVATE std::string QuicVersionToString(const QuicVersion version);

// Returns comma separated list of string representations of QuicVersion enum
// values in the supplied |versions| vector.
NET_EXPORT_PRIVATE std::string QuicVersionVectorToString(
    const QuicVersionVector& versions);

// Version and Crypto tags are written to the wire with a big-endian
// representation of the name of the tag.  For example
// the client hello tag (CHLO) will be written as the
// following 4 bytes: 'C' 'H' 'L' 'O'.  Since it is
// stored in memory as a little endian uint32, we need
// to reverse the order of the bytes.

// MakeQuicTag returns a value given the four bytes. For example:
//   MakeQuicTag('C', 'H', 'L', 'O');
NET_EXPORT_PRIVATE QuicTag MakeQuicTag(char a, char b, char c, char d);

// Returns true if the tag vector contains the specified tag.
NET_EXPORT_PRIVATE bool ContainsQuicTag(const QuicTagVector& tag_vector,
                                        QuicTag tag);

// Size in bytes of the data or fec packet header.
NET_EXPORT_PRIVATE size_t GetPacketHeaderSize(const QuicPacketHeader& header);

NET_EXPORT_PRIVATE size_t GetPacketHeaderSize(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    QuicSequenceNumberLength sequence_number_length,
    InFecGroup is_in_fec_group);

// Index of the first byte in a QUIC packet of FEC protected data.
NET_EXPORT_PRIVATE size_t GetStartOfFecProtectedData(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    QuicSequenceNumberLength sequence_number_length);
// Index of the first byte in a QUIC packet of encrypted data.
NET_EXPORT_PRIVATE size_t GetStartOfEncryptedData(
    QuicConnectionIdLength connection_id_length,
    bool include_version,
    QuicSequenceNumberLength sequence_number_length);

enum QuicRstStreamErrorCode {
  QUIC_STREAM_NO_ERROR = 0,

  // There was some error which halted stream processing.
  QUIC_ERROR_PROCESSING_STREAM,
  // We got two fin or reset offsets which did not match.
  QUIC_MULTIPLE_TERMINATION_OFFSETS,
  // We got bad payload and can not respond to it at the protocol level.
  QUIC_BAD_APPLICATION_PAYLOAD,
  // Stream closed due to connection error. No reset frame is sent when this
  // happens.
  QUIC_STREAM_CONNECTION_ERROR,
  // GoAway frame sent. No more stream can be created.
  QUIC_STREAM_PEER_GOING_AWAY,
  // The stream has been cancelled.
  QUIC_STREAM_CANCELLED,
  // Closing stream locally, sending a RST to allow for proper flow control
  // accounting. Sent in response to a RST from the peer.
  QUIC_RST_ACKNOWLEDGEMENT,

  // No error. Used as bound while iterating.
  QUIC_STREAM_LAST_ERROR,
};

// Because receiving an unknown QuicRstStreamErrorCode results in connection
// teardown, we use this to make sure any errors predating a given version are
// downgraded to the most appropriate existing error.
NET_EXPORT_PRIVATE QuicRstStreamErrorCode AdjustErrorForVersion(
    QuicRstStreamErrorCode error_code,
    QuicVersion version);

// These values must remain stable as they are uploaded to UMA histograms.
// To add a new error code, use the current value of QUIC_LAST_ERROR and
// increment QUIC_LAST_ERROR.
enum QuicErrorCode {
  QUIC_NO_ERROR = 0,

  // Connection has reached an invalid state.
  QUIC_INTERNAL_ERROR = 1,
  // There were data frames after the a fin or reset.
  QUIC_STREAM_DATA_AFTER_TERMINATION = 2,
  // Control frame is malformed.
  QUIC_INVALID_PACKET_HEADER = 3,
  // Frame data is malformed.
  QUIC_INVALID_FRAME_DATA = 4,
  // The packet contained no payload.
  QUIC_MISSING_PAYLOAD = 48,
  // FEC data is malformed.
  QUIC_INVALID_FEC_DATA = 5,
  // STREAM frame data is malformed.
  QUIC_INVALID_STREAM_DATA = 46,
  // STREAM frame data is not encrypted.
  QUIC_UNENCRYPTED_STREAM_DATA = 61,
  // RST_STREAM frame data is malformed.
  QUIC_INVALID_RST_STREAM_DATA = 6,
  // CONNECTION_CLOSE frame data is malformed.
  QUIC_INVALID_CONNECTION_CLOSE_DATA = 7,
  // GOAWAY frame data is malformed.
  QUIC_INVALID_GOAWAY_DATA = 8,
  // WINDOW_UPDATE frame data is malformed.
  QUIC_INVALID_WINDOW_UPDATE_DATA = 57,
  // BLOCKED frame data is malformed.
  QUIC_INVALID_BLOCKED_DATA = 58,
  // STOP_WAITING frame data is malformed.
  QUIC_INVALID_STOP_WAITING_DATA = 60,
  // ACK frame data is malformed.
  QUIC_INVALID_ACK_DATA = 9,

  // deprecated: QUIC_INVALID_CONGESTION_FEEDBACK_DATA = 47,

  // Version negotiation packet is malformed.
  QUIC_INVALID_VERSION_NEGOTIATION_PACKET = 10,
  // Public RST packet is malformed.
  QUIC_INVALID_PUBLIC_RST_PACKET = 11,
  // There was an error decrypting.
  QUIC_DECRYPTION_FAILURE = 12,
  // There was an error encrypting.
  QUIC_ENCRYPTION_FAILURE = 13,
  // The packet exceeded kMaxPacketSize.
  QUIC_PACKET_TOO_LARGE = 14,
  // Data was sent for a stream which did not exist.
  QUIC_PACKET_FOR_NONEXISTENT_STREAM = 15,
  // The peer is going away.  May be a client or server.
  QUIC_PEER_GOING_AWAY = 16,
  // A stream ID was invalid.
  QUIC_INVALID_STREAM_ID = 17,
  // A priority was invalid.
  QUIC_INVALID_PRIORITY = 49,
  // Too many streams already open.
  QUIC_TOO_MANY_OPEN_STREAMS = 18,
  // The peer must send a FIN/RST for each stream, and has not been doing so.
  QUIC_TOO_MANY_UNFINISHED_STREAMS = 66,
  // Received public reset for this connection.
  QUIC_PUBLIC_RESET = 19,
  // Invalid protocol version.
  QUIC_INVALID_VERSION = 20,

  // deprecated: QUIC_STREAM_RST_BEFORE_HEADERS_DECOMPRESSED = 21

  // The Header ID for a stream was too far from the previous.
  QUIC_INVALID_HEADER_ID = 22,
  // Negotiable parameter received during handshake had invalid value.
  QUIC_INVALID_NEGOTIATED_VALUE = 23,
  // There was an error decompressing data.
  QUIC_DECOMPRESSION_FAILURE = 24,
  // We hit our prenegotiated (or default) timeout
  QUIC_CONNECTION_TIMED_OUT = 25,
  // We hit our overall connection timeout
  QUIC_CONNECTION_OVERALL_TIMED_OUT = 67,
  // There was an error encountered migrating addresses
  QUIC_ERROR_MIGRATING_ADDRESS = 26,
  // There was an error while writing to the socket.
  QUIC_PACKET_WRITE_ERROR = 27,
  // There was an error while reading from the socket.
  QUIC_PACKET_READ_ERROR = 51,
  // We received a STREAM_FRAME with no data and no fin flag set.
  QUIC_INVALID_STREAM_FRAME = 50,
  // We received invalid data on the headers stream.
  QUIC_INVALID_HEADERS_STREAM_DATA = 56,
  // The peer received too much data, violating flow control.
  QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = 59,
  // The peer sent too much data, violating flow control.
  QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA = 63,
  // The peer received an invalid flow control window.
  QUIC_FLOW_CONTROL_INVALID_WINDOW = 64,
  // The connection has been IP pooled into an existing connection.
  QUIC_CONNECTION_IP_POOLED = 62,
  // The connection has too many outstanding sent packets.
  QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS = 68,
  // The connection has too many outstanding received packets.
  QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = 69,
  // The quic connection job to load server config is cancelled.
  QUIC_CONNECTION_CANCELLED = 70,

  // Crypto errors.

  // Hanshake failed.
  QUIC_HANDSHAKE_FAILED = 28,
  // Handshake message contained out of order tags.
  QUIC_CRYPTO_TAGS_OUT_OF_ORDER = 29,
  // Handshake message contained too many entries.
  QUIC_CRYPTO_TOO_MANY_ENTRIES = 30,
  // Handshake message contained an invalid value length.
  QUIC_CRYPTO_INVALID_VALUE_LENGTH = 31,
  // A crypto message was received after the handshake was complete.
  QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = 32,
  // A crypto message was received with an illegal message tag.
  QUIC_INVALID_CRYPTO_MESSAGE_TYPE = 33,
  // A crypto message was received with an illegal parameter.
  QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER = 34,
  // An invalid channel id signature was supplied.
  QUIC_INVALID_CHANNEL_ID_SIGNATURE = 52,
  // A crypto message was received with a mandatory parameter missing.
  QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = 35,
  // A crypto message was received with a parameter that has no overlap
  // with the local parameter.
  QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = 36,
  // A crypto message was received that contained a parameter with too few
  // values.
  QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND = 37,
  // An internal error occured in crypto processing.
  QUIC_CRYPTO_INTERNAL_ERROR = 38,
  // A crypto handshake message specified an unsupported version.
  QUIC_CRYPTO_VERSION_NOT_SUPPORTED = 39,
  // There was no intersection between the crypto primitives supported by the
  // peer and ourselves.
  QUIC_CRYPTO_NO_SUPPORT = 40,
  // The server rejected our client hello messages too many times.
  QUIC_CRYPTO_TOO_MANY_REJECTS = 41,
  // The client rejected the server's certificate chain or signature.
  QUIC_PROOF_INVALID = 42,
  // A crypto message was received with a duplicate tag.
  QUIC_CRYPTO_DUPLICATE_TAG = 43,
  // A crypto message was received with the wrong encryption level (i.e. it
  // should have been encrypted but was not.)
  QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT = 44,
  // The server config for a server has expired.
  QUIC_CRYPTO_SERVER_CONFIG_EXPIRED = 45,
  // We failed to setup the symmetric keys for a connection.
  QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = 53,
  // A handshake message arrived, but we are still validating the
  // previous handshake message.
  QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = 54,
  // A server config update arrived before the handshake is complete.
  QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = 65,
  // This connection involved a version negotiation which appears to have been
  // tampered with.
  QUIC_VERSION_NEGOTIATION_MISMATCH = 55,

  // No error. Used as bound while iterating.
  QUIC_LAST_ERROR = 71,
};

struct NET_EXPORT_PRIVATE QuicPacketPublicHeader {
  QuicPacketPublicHeader();
  explicit QuicPacketPublicHeader(const QuicPacketPublicHeader& other);
  ~QuicPacketPublicHeader();

  // Universal header. All QuicPacket headers will have a connection_id and
  // public flags.
  QuicConnectionId connection_id;
  QuicConnectionIdLength connection_id_length;
  bool reset_flag;
  bool version_flag;
  QuicSequenceNumberLength sequence_number_length;
  QuicVersionVector versions;
};

// An integer which cannot be a packet sequence number.
const QuicPacketSequenceNumber kInvalidPacketSequenceNumber = 0;

// Header for Data or FEC packets.
struct NET_EXPORT_PRIVATE QuicPacketHeader {
  QuicPacketHeader();
  explicit QuicPacketHeader(const QuicPacketPublicHeader& header);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicPacketHeader& s);

  QuicPacketPublicHeader public_header;
  bool fec_flag;
  bool entropy_flag;
  QuicPacketEntropyHash entropy_hash;
  QuicPacketSequenceNumber packet_sequence_number;
  InFecGroup is_in_fec_group;
  QuicFecGroupNumber fec_group;
};

struct NET_EXPORT_PRIVATE QuicPublicResetPacket {
  QuicPublicResetPacket();
  explicit QuicPublicResetPacket(const QuicPacketPublicHeader& header);

  QuicPacketPublicHeader public_header;
  QuicPublicResetNonceProof nonce_proof;
  QuicPacketSequenceNumber rejected_sequence_number;
  IPEndPoint client_address;
};

enum QuicVersionNegotiationState {
  START_NEGOTIATION = 0,
  // Server-side this implies we've sent a version negotiation packet and are
  // waiting on the client to select a compatible version.  Client-side this
  // implies we've gotten a version negotiation packet, are retransmitting the
  // initial packets with a supported version and are waiting for our first
  // packet from the server.
  NEGOTIATION_IN_PROGRESS,
  // This indicates this endpoint has received a packet from the peer with a
  // version this endpoint supports.  Version negotiation is complete, and the
  // version number will no longer be sent with future packets.
  NEGOTIATED_VERSION
};

typedef QuicPacketPublicHeader QuicVersionNegotiationPacket;

// A padding frame contains no payload.
struct NET_EXPORT_PRIVATE QuicPaddingFrame {
};

// A ping frame contains no payload, though it is retransmittable,
// and ACK'd just like other normal frames.
struct NET_EXPORT_PRIVATE QuicPingFrame {
};

struct NET_EXPORT_PRIVATE QuicStreamFrame {
  QuicStreamFrame();
  QuicStreamFrame(const QuicStreamFrame& frame);
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  IOVector data);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicStreamFrame& s);

  // Returns a copy of the IOVector |data| as a heap-allocated string.
  // Caller must take ownership of the returned string.
  std::string* GetDataAsString() const;

  QuicStreamId stream_id;
  bool fin;
  QuicStreamOffset offset;  // Location of this data in the stream.
  IOVector data;
};

// TODO(ianswett): Re-evaluate the trade-offs of hash_set vs set when framing
// is finalized.
typedef std::set<QuicPacketSequenceNumber> SequenceNumberSet;
typedef std::list<QuicPacketSequenceNumber> SequenceNumberList;

typedef std::list<
    std::pair<QuicPacketSequenceNumber, QuicTime> > PacketTimeList;

struct NET_EXPORT_PRIVATE QuicStopWaitingFrame {
  QuicStopWaitingFrame();
  ~QuicStopWaitingFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicStopWaitingFrame& s);
  // Entropy hash of all packets up to, but not including, the least unacked
  // packet.
  QuicPacketEntropyHash entropy_hash;
  // The lowest packet we've sent which is unacked, and we expect an ack for.
  QuicPacketSequenceNumber least_unacked;
};

struct NET_EXPORT_PRIVATE QuicAckFrame {
  QuicAckFrame();
  ~QuicAckFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicAckFrame& s);

  // Entropy hash of all packets up to largest observed not including missing
  // packets.
  QuicPacketEntropyHash entropy_hash;

  // The highest packet sequence number we've observed from the peer.
  //
  // In general, this should be the largest packet number we've received.  In
  // the case of truncated acks, we may have to advertise a lower "upper bound"
  // than largest received, to avoid implicitly acking missing packets that
  // don't fit in the missing packet list due to size limitations.  In this
  // case, largest_observed may be a packet which is also in the missing packets
  // list.
  QuicPacketSequenceNumber largest_observed;

  // Time elapsed since largest_observed was received until this Ack frame was
  // sent.
  QuicTime::Delta delta_time_largest_observed;

  // TODO(satyamshekhar): Can be optimized using an interval set like data
  // structure.
  // The set of packets which we're expecting and have not received.
  SequenceNumberSet missing_packets;

  // Whether the ack had to be truncated when sent.
  bool is_truncated;

  // Packets which have been revived via FEC.
  // All of these must also be in missing_packets.
  SequenceNumberSet revived_packets;

  // List of <sequence_number, time> for when packets arrived.
  PacketTimeList received_packet_times;
};

// True if the sequence number is greater than largest_observed or is listed
// as missing.
// Always returns false for sequence numbers less than least_unacked.
bool NET_EXPORT_PRIVATE IsAwaitingPacket(
    const QuicAckFrame& ack_frame,
    QuicPacketSequenceNumber sequence_number);

// Inserts missing packets between [lower, higher).
void NET_EXPORT_PRIVATE InsertMissingPacketsBetween(
    QuicAckFrame* ack_frame,
    QuicPacketSequenceNumber lower,
    QuicPacketSequenceNumber higher);

// Defines for all types of congestion control algorithms that can be used in
// QUIC. Note that this is separate from the congestion feedback type -
// some congestion control algorithms may use the same feedback type
// (Reno and Cubic are the classic example for that).
enum CongestionControlType {
  kCubic,
  kReno,
  kBBR,
};

enum LossDetectionType {
  kNack,  // Used to mimic TCP's loss detection.
  kTime,  // Time based loss detection.
};

struct NET_EXPORT_PRIVATE QuicRstStreamFrame {
  QuicRstStreamFrame();
  QuicRstStreamFrame(QuicStreamId stream_id,
                     QuicRstStreamErrorCode error_code,
                     QuicStreamOffset bytes_written);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicRstStreamFrame& r);

  QuicStreamId stream_id;
  QuicRstStreamErrorCode error_code;
  std::string error_details;

  // Used to update flow control windows. On termination of a stream, both
  // endpoints must inform the peer of the number of bytes they have sent on
  // that stream. This can be done through normal termination (data packet with
  // FIN) or through a RST.
  QuicStreamOffset byte_offset;
};

struct NET_EXPORT_PRIVATE QuicConnectionCloseFrame {
  QuicConnectionCloseFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicConnectionCloseFrame& c);

  QuicErrorCode error_code;
  std::string error_details;
};

struct NET_EXPORT_PRIVATE QuicGoAwayFrame {
  QuicGoAwayFrame();
  QuicGoAwayFrame(QuicErrorCode error_code,
                  QuicStreamId last_good_stream_id,
                  const std::string& reason);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicGoAwayFrame& g);

  QuicErrorCode error_code;
  QuicStreamId last_good_stream_id;
  std::string reason_phrase;
};

// Flow control updates per-stream and at the connection levoel.
// Based on SPDY's WINDOW_UPDATE frame, but uses an absolute byte offset rather
// than a window delta.
// TODO(rjshade): A possible future optimization is to make stream_id and
//                byte_offset variable length, similar to stream frames.
struct NET_EXPORT_PRIVATE QuicWindowUpdateFrame {
  QuicWindowUpdateFrame() {}
  QuicWindowUpdateFrame(QuicStreamId stream_id, QuicStreamOffset byte_offset);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicWindowUpdateFrame& w);

  // The stream this frame applies to.  0 is a special case meaning the overall
  // connection rather than a specific stream.
  QuicStreamId stream_id;

  // Byte offset in the stream or connection. The receiver of this frame must
  // not send data which would result in this offset being exceeded.
  QuicStreamOffset byte_offset;
};

// The BLOCKED frame is used to indicate to the remote endpoint that this
// endpoint believes itself to be flow-control blocked but otherwise ready to
// send data. The BLOCKED frame is purely advisory and optional.
// Based on SPDY's BLOCKED frame (undocumented as of 2014-01-28).
struct NET_EXPORT_PRIVATE QuicBlockedFrame {
  QuicBlockedFrame() {}
  explicit QuicBlockedFrame(QuicStreamId stream_id);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicBlockedFrame& b);

  // The stream this frame applies to.  0 is a special case meaning the overall
  // connection rather than a specific stream.
  QuicStreamId stream_id;
};

// EncryptionLevel enumerates the stages of encryption that a QUIC connection
// progresses through. When retransmitting a packet, the encryption level needs
// to be specified so that it is retransmitted at a level which the peer can
// understand.
enum EncryptionLevel {
  ENCRYPTION_NONE = 0,
  ENCRYPTION_INITIAL = 1,
  ENCRYPTION_FORWARD_SECURE = 2,

  NUM_ENCRYPTION_LEVELS,
};

struct NET_EXPORT_PRIVATE QuicFrame {
  QuicFrame();
  explicit QuicFrame(QuicPaddingFrame* padding_frame);
  explicit QuicFrame(QuicStreamFrame* stream_frame);
  explicit QuicFrame(QuicAckFrame* frame);

  explicit QuicFrame(QuicRstStreamFrame* frame);
  explicit QuicFrame(QuicConnectionCloseFrame* frame);
  explicit QuicFrame(QuicStopWaitingFrame* frame);
  explicit QuicFrame(QuicPingFrame* frame);
  explicit QuicFrame(QuicGoAwayFrame* frame);
  explicit QuicFrame(QuicWindowUpdateFrame* frame);
  explicit QuicFrame(QuicBlockedFrame* frame);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicFrame& frame);

  QuicFrameType type;
  union {
    QuicPaddingFrame* padding_frame;
    QuicStreamFrame* stream_frame;
    QuicAckFrame* ack_frame;

    QuicStopWaitingFrame* stop_waiting_frame;

    QuicPingFrame* ping_frame;
    QuicRstStreamFrame* rst_stream_frame;
    QuicConnectionCloseFrame* connection_close_frame;
    QuicGoAwayFrame* goaway_frame;
    QuicWindowUpdateFrame* window_update_frame;
    QuicBlockedFrame* blocked_frame;
  };
};

typedef std::vector<QuicFrame> QuicFrames;

struct NET_EXPORT_PRIVATE QuicFecData {
  QuicFecData();

  // The FEC group number is also the sequence number of the first
  // FEC protected packet.  The last protected packet's sequence number will
  // be one less than the sequence number of the FEC packet.
  QuicFecGroupNumber fec_group;
  base::StringPiece redundancy;
};

class NET_EXPORT_PRIVATE QuicData {
 public:
  QuicData(const char* buffer, size_t length);
  QuicData(char* buffer, size_t length, bool owns_buffer);
  virtual ~QuicData();

  base::StringPiece AsStringPiece() const {
    return base::StringPiece(data(), length());
  }

  const char* data() const { return buffer_; }
  size_t length() const { return length_; }

 private:
  const char* buffer_;
  size_t length_;
  bool owns_buffer_;

  DISALLOW_COPY_AND_ASSIGN(QuicData);
};

class NET_EXPORT_PRIVATE QuicPacket : public QuicData {
 public:
  QuicPacket(char* buffer,
             size_t length,
             bool owns_buffer,
             QuicConnectionIdLength connection_id_length,
             bool includes_version,
             QuicSequenceNumberLength sequence_number_length);

  base::StringPiece FecProtectedData() const;
  base::StringPiece AssociatedData() const;
  base::StringPiece BeforePlaintext() const;
  base::StringPiece Plaintext() const;

  char* mutable_data() { return buffer_; }

 private:
  char* buffer_;
  const QuicConnectionIdLength connection_id_length_;
  const bool includes_version_;
  const QuicSequenceNumberLength sequence_number_length_;

  DISALLOW_COPY_AND_ASSIGN(QuicPacket);
};

class NET_EXPORT_PRIVATE QuicEncryptedPacket : public QuicData {
 public:
  QuicEncryptedPacket(const char* buffer, size_t length);
  QuicEncryptedPacket(char* buffer, size_t length, bool owns_buffer);

  // Clones the packet into a new packet which owns the buffer.
  QuicEncryptedPacket* Clone() const;

  // By default, gtest prints the raw bytes of an object. The bool data
  // member (in the base class QuicData) causes this object to have padding
  // bytes, which causes the default gtest object printer to read
  // uninitialize memory. So we need to teach gtest how to print this object.
  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os, const QuicEncryptedPacket& s);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicEncryptedPacket);
};

class NET_EXPORT_PRIVATE RetransmittableFrames {
 public:
  explicit RetransmittableFrames(EncryptionLevel level);
  ~RetransmittableFrames();

  // Allocates a local copy of the referenced StringPiece has QuicStreamFrame
  // use it.
  // Takes ownership of |stream_frame|.
  const QuicFrame& AddStreamFrame(QuicStreamFrame* stream_frame);
  // Takes ownership of the frame inside |frame|.
  const QuicFrame& AddNonStreamFrame(const QuicFrame& frame);
  const QuicFrames& frames() const { return frames_; }

  IsHandshake HasCryptoHandshake() const {
    return has_crypto_handshake_;
  }

  EncryptionLevel encryption_level() const {
    return encryption_level_;
  }

 private:
  QuicFrames frames_;
  const EncryptionLevel encryption_level_;
  IsHandshake has_crypto_handshake_;
  // Data referenced by the StringPiece of a QuicStreamFrame.
  std::vector<std::string*> stream_data_;

  DISALLOW_COPY_AND_ASSIGN(RetransmittableFrames);
};

struct NET_EXPORT_PRIVATE SerializedPacket {
  SerializedPacket(QuicPacketSequenceNumber sequence_number,
                   QuicSequenceNumberLength sequence_number_length,
                   QuicEncryptedPacket* packet,
                   QuicPacketEntropyHash entropy_hash,
                   RetransmittableFrames* retransmittable_frames);
  ~SerializedPacket();

  QuicPacketSequenceNumber sequence_number;
  QuicSequenceNumberLength sequence_number_length;
  QuicEncryptedPacket* packet;
  QuicPacketEntropyHash entropy_hash;
  RetransmittableFrames* retransmittable_frames;
  bool is_fec_packet;

  // Optional notifiers which will be informed when this packet has been ACKed.
  std::list<QuicAckNotifier*> notifiers;
};

struct NET_EXPORT_PRIVATE TransmissionInfo {
  // Used by STL when assigning into a map.
  TransmissionInfo();

  // Constructs a Transmission with a new all_tranmissions set
  // containing |sequence_number|.
  TransmissionInfo(RetransmittableFrames* retransmittable_frames,
                   QuicSequenceNumberLength sequence_number_length,
                   TransmissionType transmission_type,
                   QuicTime sent_time,
                   QuicByteCount bytes_sent,
                   bool is_fec_packet);

  RetransmittableFrames* retransmittable_frames;
  QuicSequenceNumberLength sequence_number_length;
  QuicTime sent_time;
  QuicByteCount bytes_sent;
  QuicPacketCount nack_count;
  // Reason why this packet was transmitted.
  TransmissionType transmission_type;
  // Stores the sequence numbers of all transmissions of this packet.
  // Must always be nullptr or have multiple elements.
  SequenceNumberList* all_transmissions;
  // In flight packets have not been abandoned or lost.
  bool in_flight;
  // True if the packet can never be acked, so it can be removed.
  bool is_unackable;
  // True if the packet is an FEC packet.
  bool is_fec_packet;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PROTOCOL_H_
