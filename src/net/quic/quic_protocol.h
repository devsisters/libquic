// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_PROTOCOL_H_
#define NET_QUIC_QUIC_PROTOCOL_H_

#include <stddef.h>
#include <stdint.h>

#include <limits>
#include <list>
#include <map>
#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/iovec.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_export.h"
#include "net/quic/interval_set.h"
#include "net/quic/quic_bandwidth.h"
#include "net/quic/quic_time.h"
#include "net/quic/quic_types.h"

namespace net {

class QuicPacket;
struct QuicPacketHeader;
class QuicAckListenerInterface;

typedef uint64_t QuicConnectionId;
typedef uint32_t QuicStreamId;
typedef uint64_t QuicStreamOffset;
typedef uint64_t QuicPacketNumber;
typedef uint8_t QuicPathId;
typedef uint64_t QuicPublicResetNonceProof;
typedef uint8_t QuicPacketEntropyHash;
typedef uint32_t QuicHeaderId;
// QuicTag is the type of a tag in the wire protocol.
typedef uint32_t QuicTag;
typedef std::vector<QuicTag> QuicTagVector;
typedef std::map<QuicTag, std::string> QuicTagValueMap;
typedef uint16_t QuicPacketLength;

// Default initial maximum size in bytes of a QUIC packet.
const QuicByteCount kDefaultMaxPacketSize = 1350;
// Default initial maximum size in bytes of a QUIC packet for servers.
const QuicByteCount kDefaultServerMaxPacketSize = 1000;
// The maximum packet size of any QUIC packet, based on ethernet's max size,
// minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
const QuicByteCount kMaxPacketSize = 1452;
// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
const QuicByteCount kDefaultTCPMSS = 1460;

// We match SPDY's use of 32 (since we'd compete with SPDY).
const QuicPacketCount kInitialCongestionWindow = 32;

// Minimum size of initial flow control window, for both stream and session.
const uint32_t kMinimumFlowControlSendWindow = 16 * 1024;  // 16 KB

// Maximum flow control receive window limits for connection and stream.
const QuicByteCount kStreamReceiveWindowLimit = 16 * 1024 * 1024;   // 16 MB
const QuicByteCount kSessionReceiveWindowLimit = 24 * 1024 * 1024;  // 24 MB

// Minimum size of the CWND, in packets, when doing bandwidth resumption.
const QuicPacketCount kMinCongestionWindowForBandwidthResumption = 10;

// Maximum number of tracked packets.
const QuicPacketCount kMaxTrackedPackets = 10000;

// Default size of the socket receive buffer in bytes.
const QuicByteCount kDefaultSocketReceiveBuffer = 1024 * 1024;
// Minimum size of the socket receive buffer in bytes.
// Smaller values are ignored.
const QuicByteCount kMinSocketReceiveBuffer = 16 * 1024;

// Fraction of the receive buffer that can be used, based on conservative
// estimates and testing on Linux.
// An alternative to kUsableRecieveBufferFraction.
static const float kConservativeReceiveBufferFraction = 0.6f;

// Don't allow a client to suggest an RTT shorter than 10ms.
const uint32_t kMinInitialRoundTripTimeUs = 10 * kNumMicrosPerMilli;

// Don't allow a client to suggest an RTT longer than 15 seconds.
const uint32_t kMaxInitialRoundTripTimeUs = 15 * kNumMicrosPerSecond;

// Maximum number of open streams per connection.
const size_t kDefaultMaxStreamsPerConnection = 100;

// Number of bytes reserved for public flags in the packet header.
const size_t kPublicFlagsSize = 1;
// Number of bytes reserved for version number in the packet header.
const size_t kQuicVersionSize = 4;
// Number of bytes reserved for path id in the packet header.
const size_t kQuicPathIdSize = 1;
// Number of bytes reserved for private flags in the packet header.
const size_t kPrivateFlagsSize = 1;

// Signifies that the QuicPacket will contain version of the protocol.
const bool kIncludeVersion = true;
// Signifies that the QuicPacket will contain path id.
const bool kIncludePathId = true;
// Signifies that the QuicPacket will include a diversification nonce.
const bool kIncludeDiversificationNonce = true;

// Stream ID is reserved to denote an invalid ID.
const QuicStreamId kInvalidStreamId = 0;

// Reserved ID for the crypto stream.
const QuicStreamId kCryptoStreamId = 1;

// Reserved ID for the headers stream.
const QuicStreamId kHeadersStreamId = 3;

// Header key used to identify final offset on data stream when sending HTTP/2
// trailing headers over QUIC.
NET_EXPORT_PRIVATE extern const char* const kFinalOffsetHeaderKey;

// Maximum delayed ack time, in ms.
const int64_t kMaxDelayedAckTimeMs = 25;

// Minimum tail loss probe time in ms.
static const int64_t kMinTailLossProbeTimeoutMs = 10;

// The timeout before the handshake succeeds.
const int64_t kInitialIdleTimeoutSecs = 5;
// The default idle timeout.
const int64_t kDefaultIdleTimeoutSecs = 30;
// The maximum idle timeout that can be negotiated.
const int64_t kMaximumIdleTimeoutSecs = 60 * 10;  // 10 minutes.
// The default timeout for a connection until the crypto handshake succeeds.
const int64_t kMaxTimeForCryptoHandshakeSecs = 10;  // 10 secs.

// Default limit on the number of undecryptable packets the connection buffers
// before the CHLO/SHLO arrive.
const size_t kDefaultMaxUndecryptablePackets = 10;

// Default ping timeout.
const int64_t kPingTimeoutSecs = 15;  // 15 secs.

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

// Available streams are ones with IDs less than the highest stream that has
// been opened which have neither been opened or reset. The limit on the number
// of available streams is 10 times the limit on the number of open streams.
const int kMaxAvailableStreamsMultiplier = 10;

// Track the number of promises that are not yet claimed by a
// corresponding get.  This must be smaller than
// kMaxAvailableStreamsMultiplier, because RST on a promised stream my
// create available streams entries.
const int kMaxPromisedStreamsMultiplier = kMaxAvailableStreamsMultiplier - 1;

// TCP RFC calls for 1 second RTO however Linux differs from this default and
// define the minimum RTO to 200ms, we will use the same until we have data to
// support a higher or lower value.
static const int64_t kMinRetransmissionTimeMs = 200;

// We define an unsigned 16-bit floating point value, inspired by IEEE floats
// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
// bit) and denormals, but without signs, transfinites or fractions. Wire format
// 16 bits (little-endian byte order) are split into exponent (high 5) and
// mantissa (low 11) and decoded as:
//   uint64_t value;
//   if (exponent == 0) value = mantissa;
//   else value = (mantissa | 1 << 11) << (exponent - 1)
const int kUFloat16ExponentBits = 5;
const int kUFloat16MaxExponent = (1 << kUFloat16ExponentBits) - 2;     // 30
const int kUFloat16MantissaBits = 16 - kUFloat16ExponentBits;          // 11
const int kUFloat16MantissaEffectiveBits = kUFloat16MantissaBits + 1;  // 12
const uint64_t kUFloat16MaxValue =  // 0x3FFC0000000
    ((UINT64_C(1) << kUFloat16MantissaEffectiveBits) - 1)
    << kUFloat16MaxExponent;

// Default path ID.
const QuicPathId kDefaultPathId = 0;
// Invalid path ID.
const QuicPathId kInvalidPathId = 0xff;

// kDiversificationNonceSize is the size, in bytes, of the nonce that a server
// may set in the packet header to ensure that its INITIAL keys are not
// duplicated.
const size_t kDiversificationNonceSize = 32;

enum TransmissionType : int8_t {
  NOT_RETRANSMISSION,
  FIRST_TRANSMISSION_TYPE = NOT_RETRANSMISSION,
  HANDSHAKE_RETRANSMISSION,    // Retransmits due to handshake timeouts.
  ALL_UNACKED_RETRANSMISSION,  // Retransmits all unacked packets.
  ALL_INITIAL_RETRANSMISSION,  // Retransmits all initially encrypted packets.
  LOSS_RETRANSMISSION,         // Retransmits due to loss detection.
  RTO_RETRANSMISSION,          // Retransmits due to retransmit time out.
  TLP_RETRANSMISSION,          // Tail loss probes.
  LAST_TRANSMISSION_TYPE = TLP_RETRANSMISSION,
};

enum HasRetransmittableData : int8_t {
  NO_RETRANSMITTABLE_DATA,
  HAS_RETRANSMITTABLE_DATA,
};

enum IsHandshake : int8_t { NOT_HANDSHAKE, IS_HANDSHAKE };

enum class Perspective { IS_SERVER, IS_CLIENT };

// Describes whether a ConnectionClose was originated by the peer.
enum class ConnectionCloseSource { FROM_PEER, FROM_SELF };

// Should a connection be closed silently or not.
enum class ConnectionCloseBehavior {
  SILENT_CLOSE,
  SEND_CONNECTION_CLOSE_PACKET
};

NET_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                            const Perspective& s);
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
  PATH_CLOSE_FRAME = 8,

  // STREAM and ACK frames are special frames. They are encoded differently on
  // the wire and their values do not need to be stable.
  STREAM_FRAME,
  ACK_FRAME,
  // The path MTU discovery frame is encoded as a PING frame on the wire.
  MTU_DISCOVERY_FRAME,
  NUM_FRAME_TYPES
};

enum QuicConnectionIdLength {
  PACKET_0BYTE_CONNECTION_ID = 0,
  PACKET_8BYTE_CONNECTION_ID = 8
};

enum QuicPacketNumberLength : int8_t {
  PACKET_1BYTE_PACKET_NUMBER = 1,
  PACKET_2BYTE_PACKET_NUMBER = 2,
  PACKET_4BYTE_PACKET_NUMBER = 4,
  PACKET_6BYTE_PACKET_NUMBER = 6
};

// Used to indicate a QuicSequenceNumberLength using two flag bits.
enum QuicPacketNumberLengthFlags {
  PACKET_FLAGS_1BYTE_PACKET = 0,           // 00
  PACKET_FLAGS_2BYTE_PACKET = 1,           // 01
  PACKET_FLAGS_4BYTE_PACKET = 1 << 1,      // 10
  PACKET_FLAGS_6BYTE_PACKET = 1 << 1 | 1,  // 11
};

// The public flags are specified in one byte.
enum QuicPacketPublicFlags {
  PACKET_PUBLIC_FLAGS_NONE = 0,

  // Bit 0: Does the packet header contains version info?
  PACKET_PUBLIC_FLAGS_VERSION = 1 << 0,

  // Bit 1: Is this packet a public reset packet?
  PACKET_PUBLIC_FLAGS_RST = 1 << 1,

  // Bit 2: indicates the that public header includes a nonce.
  PACKET_PUBLIC_FLAGS_NONCE = 1 << 2,

  // Bit 3: indicates whether a ConnectionID is included.
  PACKET_PUBLIC_FLAGS_0BYTE_CONNECTION_ID = 0,
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID = 1 << 3,

  // QUIC_VERSION_32 and earlier use two bits for an 8 byte
  // connection id.
  PACKET_PUBLIC_FLAGS_8BYTE_CONNECTION_ID_OLD = 1 << 3 | 1 << 2,

  // Bits 4 and 5 describe the packet number length as follows:
  // --00----: 1 byte
  // --01----: 2 bytes
  // --10----: 4 bytes
  // --11----: 6 bytes
  PACKET_PUBLIC_FLAGS_1BYTE_PACKET = PACKET_FLAGS_1BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_2BYTE_PACKET = PACKET_FLAGS_2BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_4BYTE_PACKET = PACKET_FLAGS_4BYTE_PACKET << 4,
  PACKET_PUBLIC_FLAGS_6BYTE_PACKET = PACKET_FLAGS_6BYTE_PACKET << 4,

  // Bit 6: Does the packet header contain a path id?
  PACKET_PUBLIC_FLAGS_MULTIPATH = 1 << 6,

  // Reserved, unimplemented flags:

  // Bit 7: indicates the presence of a second flags byte.
  PACKET_PUBLIC_FLAGS_TWO_OR_MORE_BYTES = 1 << 7,

  // All bits set (bit 7 is not currently used): 01111111
  PACKET_PUBLIC_FLAGS_MAX = (1 << 7) - 1,
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
  PACKET_PRIVATE_FLAGS_MAX = (1 << 3) - 1,

  // For version 32 (bits 1-7 are not used): 00000001
  PACKET_PRIVATE_FLAGS_MAX_VERSION_32 = (1 << 1) - 1
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

  QUIC_VERSION_25 = 25,  // SPDY/4 header keys, and removal of error_details
                         // from QuicRstStreamFrame
  QUIC_VERSION_26 = 26,  // In CHLO, send XLCT tag containing hash of leaf cert
  QUIC_VERSION_27 = 27,  // Sends a nonce in the SHLO.
  QUIC_VERSION_28 = 28,  // Receiver can refuse to create a requested stream.
  QUIC_VERSION_29 = 29,  // Server and client honor QUIC_STREAM_NO_ERROR.
  QUIC_VERSION_30 = 30,  // Add server side support of cert transparency.
  QUIC_VERSION_31 = 31,  // Adds a hash of the client hello to crypto proof.
  QUIC_VERSION_32 = 32,  // FEC related fields are removed from wire format.
  QUIC_VERSION_33 = 33,  // Adds diversification nonces.
  QUIC_VERSION_34 = 34,  // Deprecates entropy, removes private flag from packet
                         // header, uses new ack and stop waiting wire format.
  QUIC_VERSION_35 = 35,  // Allows endpoints to independently set stream limit.
};

// This vector contains QUIC versions which we currently support.
// This should be ordered such that the highest supported version is the first
// element, with subsequent elements in descending order (versions can be
// skipped as necessary).
//
// IMPORTANT: if you are adding to this list, follow the instructions at
// http://sites/quic/adding-and-removing-versions
static const QuicVersion kSupportedQuicVersions[] = {
    QUIC_VERSION_35, QUIC_VERSION_34, QUIC_VERSION_33, QUIC_VERSION_32,
    QUIC_VERSION_31, QUIC_VERSION_30, QUIC_VERSION_29, QUIC_VERSION_28,
    QUIC_VERSION_27, QUIC_VERSION_26, QUIC_VERSION_25};

typedef std::vector<QuicVersion> QuicVersionVector;

// Returns a vector of QUIC versions in kSupportedQuicVersions.
NET_EXPORT_PRIVATE QuicVersionVector QuicSupportedVersions();

// Returns a vector of QUIC versions from |versions| which exclude any versions
// which are disabled by flags.
NET_EXPORT_PRIVATE QuicVersionVector
FilterSupportedVersions(QuicVersionVector versions);

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
// stored in memory as a little endian uint32_t, we need
// to reverse the order of the bytes.

// MakeQuicTag returns a value given the four bytes. For example:
//   MakeQuicTag('C', 'H', 'L', 'O');
NET_EXPORT_PRIVATE QuicTag MakeQuicTag(char a, char b, char c, char d);

// Returns true if the tag vector contains the specified tag.
NET_EXPORT_PRIVATE bool ContainsQuicTag(const QuicTagVector& tag_vector,
                                        QuicTag tag);

// Size in bytes of the data packet header.
NET_EXPORT_PRIVATE size_t GetPacketHeaderSize(QuicVersion version,
                                              const QuicPacketHeader& header);

NET_EXPORT_PRIVATE size_t
GetPacketHeaderSize(QuicVersion version,
                    QuicConnectionIdLength connection_id_length,
                    bool include_version,
                    bool include_path_id,
                    bool include_diversification_nonce,
                    QuicPacketNumberLength packet_number_length);

// Index of the first byte in a QUIC packet of encrypted data.
NET_EXPORT_PRIVATE size_t
GetStartOfEncryptedData(QuicVersion version, const QuicPacketHeader& header);

NET_EXPORT_PRIVATE size_t
GetStartOfEncryptedData(QuicVersion version,
                        QuicConnectionIdLength connection_id_length,
                        bool include_version,
                        bool include_path_id,
                        bool include_diversification_nonce,
                        QuicPacketNumberLength packet_number_length);

enum QuicRstStreamErrorCode {
  // Complete response has been sent, sending a RST to ask the other endpoint
  // to stop sending request data without discarding the response.
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
  // Receiver refused to create the stream (because its limit on open streams
  // has been reached).  The sender should retry the request later (using
  // another stream).
  QUIC_REFUSED_STREAM,
  // Invalid URL in PUSH_PROMISE request header.
  QUIC_INVALID_PROMISE_URL,
  // Server is not authoritative for this URL.
  QUIC_UNAUTHORIZED_PROMISE_URL,
  // Can't have more than one active PUSH_PROMISE per URL.
  QUIC_DUPLICATE_PROMISE_URL,
  // Vary check failed.
  QUIC_PROMISE_VARY_MISMATCH,
  // Only GET and HEAD methods allowed.
  QUIC_INVALID_PROMISE_METHOD,
  // No error. Used as bound while iterating.
  QUIC_STREAM_LAST_ERROR,
};
// QUIC error codes are encoded to a single octet on-the-wire.
static_assert(static_cast<int>(QUIC_STREAM_LAST_ERROR) <=
                  std::numeric_limits<uint8_t>::max(),
              "QuicErrorCode exceeds single octet");

// Because receiving an unknown QuicRstStreamErrorCode results in connection
// teardown, we use this to make sure any errors predating a given version are
// downgraded to the most appropriate existing error.
NET_EXPORT_PRIVATE QuicRstStreamErrorCode
AdjustErrorForVersion(QuicRstStreamErrorCode error_code, QuicVersion version);

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
  // STREAM frame data overlaps with buffered data.
  QUIC_OVERLAPPING_STREAM_DATA = 87,
  // Received STREAM frame data is not encrypted.
  QUIC_UNENCRYPTED_STREAM_DATA = 61,
  // Attempt to send unencrypted STREAM frame.
  QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA = 88,
  // Received a frame which is likely the result of memory corruption.
  QUIC_MAYBE_CORRUPTED_MEMORY = 89,
  // FEC frame data is not encrypted.
  QUIC_UNENCRYPTED_FEC_DATA = 77,
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
  // PATH_CLOSE frame data is malformed.
  QUIC_INVALID_PATH_CLOSE_DATA = 78,
  // ACK frame data is malformed.
  QUIC_INVALID_ACK_DATA = 9,

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
  // The peer is going away.  May be a client or server.
  QUIC_PEER_GOING_AWAY = 16,
  // A stream ID was invalid.
  QUIC_INVALID_STREAM_ID = 17,
  // A priority was invalid.
  QUIC_INVALID_PRIORITY = 49,
  // Too many streams already open.
  QUIC_TOO_MANY_OPEN_STREAMS = 18,
  // The peer created too many available streams.
  QUIC_TOO_MANY_AVAILABLE_STREAMS = 76,
  // Received public reset for this connection.
  QUIC_PUBLIC_RESET = 19,
  // Invalid protocol version.
  QUIC_INVALID_VERSION = 20,

  // The Header ID for a stream was too far from the previous.
  QUIC_INVALID_HEADER_ID = 22,
  // Negotiable parameter received during handshake had invalid value.
  QUIC_INVALID_NEGOTIATED_VALUE = 23,
  // There was an error decompressing data.
  QUIC_DECOMPRESSION_FAILURE = 24,
  // The connection timed out due to no network activity.
  QUIC_NETWORK_IDLE_TIMEOUT = 25,
  // The connection timed out waiting for the handshake to complete.
  QUIC_HANDSHAKE_TIMEOUT = 67,
  // There was an error encountered migrating addresses.
  QUIC_ERROR_MIGRATING_ADDRESS = 26,
  // There was an error encountered migrating port only.
  QUIC_ERROR_MIGRATING_PORT = 86,
  // There was an error while writing to the socket.
  QUIC_PACKET_WRITE_ERROR = 27,
  // There was an error while reading from the socket.
  QUIC_PACKET_READ_ERROR = 51,
  // We received a STREAM_FRAME with no data and no fin flag set.
  QUIC_EMPTY_STREAM_FRAME_NO_FIN = 50,
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
  // The quic connection has been cancelled.
  QUIC_CONNECTION_CANCELLED = 70,
  // Disabled QUIC because of high packet loss rate.
  QUIC_BAD_PACKET_LOSS_RATE = 71,
  // Disabled QUIC because of too many PUBLIC_RESETs post handshake.
  QUIC_PUBLIC_RESETS_POST_HANDSHAKE = 73,
  // Disabled QUIC because of too many timeouts with streams open.
  QUIC_TIMEOUTS_WITH_OPEN_STREAMS = 74,
  // Closed because we failed to serialize a packet.
  QUIC_FAILED_TO_SERIALIZE_PACKET = 75,
  // QUIC timed out after too many RTOs.
  QUIC_TOO_MANY_RTOS = 85,

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
  // A crypto handshake message resulted in a stateless reject.
  QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT = 72,
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
  // CHLO cannot fit in one packet.
  QUIC_CRYPTO_CHLO_TOO_LARGE = 90,
  // This connection involved a version negotiation which appears to have been
  // tampered with.
  QUIC_VERSION_NEGOTIATION_MISMATCH = 55,

  // Multipath is not enabled, but a packet with multipath flag on is received.
  QUIC_BAD_MULTIPATH_FLAG = 79,

  // IP address changed causing connection close.
  QUIC_IP_ADDRESS_CHANGED = 80,

  // Connection migration errors.
  // Network changed, but connection had no migratable streams.
  QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS = 81,
  // Connection changed networks too many times.
  QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES = 82,
  // Connection migration was attempted, but there was no new network to
  // migrate to.
  QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK = 83,
  // Network changed, but connection had one or more non-migratable streams.
  QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM = 84,

  // No error. Used as bound while iterating.
  QUIC_LAST_ERROR = 91,
};

typedef char DiversificationNonce[32];

struct NET_EXPORT_PRIVATE QuicPacketPublicHeader {
  QuicPacketPublicHeader();
  explicit QuicPacketPublicHeader(const QuicPacketPublicHeader& other);
  ~QuicPacketPublicHeader();

  // Universal header. All QuicPacket headers will have a connection_id and
  // public flags.
  QuicConnectionId connection_id;
  QuicConnectionIdLength connection_id_length;
  bool multipath_flag;
  bool reset_flag;
  bool version_flag;
  QuicPacketNumberLength packet_number_length;
  QuicVersionVector versions;
  // nonce contains an optional, 32-byte nonce value. If not included in the
  // packet, |nonce| will be empty.
  DiversificationNonce* nonce;
};

// An integer which cannot be a packet number.
const QuicPacketNumber kInvalidPacketNumber = 0;

// Header for Data packets.
struct NET_EXPORT_PRIVATE QuicPacketHeader {
  QuicPacketHeader();
  explicit QuicPacketHeader(const QuicPacketPublicHeader& header);
  QuicPacketHeader(const QuicPacketHeader& other);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicPacketHeader& s);

  QuicPacketPublicHeader public_header;
  QuicPacketNumber packet_number;
  QuicPathId path_id;
  bool entropy_flag;
  QuicPacketEntropyHash entropy_hash;
  bool fec_flag;
};

struct NET_EXPORT_PRIVATE QuicPublicResetPacket {
  QuicPublicResetPacket();
  explicit QuicPublicResetPacket(const QuicPacketPublicHeader& header);

  QuicPacketPublicHeader public_header;
  QuicPublicResetNonceProof nonce_proof;
  QuicPacketNumber rejected_packet_number;
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
  QuicPaddingFrame() : num_padding_bytes(-1) {}
  explicit QuicPaddingFrame(int num_padding_bytes)
      : num_padding_bytes(num_padding_bytes) {}

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicPaddingFrame& s);

  // -1: full padding to the end of a max-sized packet
  // otherwise: only pad up to num_padding_bytes bytes
  int num_padding_bytes;
};

// A ping frame contains no payload, though it is retransmittable,
// and ACK'd just like other normal frames.
struct NET_EXPORT_PRIVATE QuicPingFrame {};

// A path MTU discovery frame contains no payload and is serialized as a ping
// frame.
struct NET_EXPORT_PRIVATE QuicMtuDiscoveryFrame {};

class NET_EXPORT_PRIVATE QuicBufferAllocator {
 public:
  virtual ~QuicBufferAllocator();

  // Returns or allocates a new buffer of |size|. Never returns null.
  virtual char* New(size_t size) = 0;

  // Returns or allocates a new buffer of |size| if |flag_enable| is true.
  // Otherwise, returns a buffer that is compatible with this class directly
  // with operator new. Never returns null.
  virtual char* New(size_t size, bool flag_enable) = 0;

  // Releases a buffer.
  virtual void Delete(char* buffer) = 0;

  // Marks the allocator as being idle. Serves as a hint to notify the allocator
  // that it should release any resources it's still holding on to.
  virtual void MarkAllocatorIdle() {}
};

// Deleter for stream buffers. Copyable to support platforms where the deleter
// of a unique_ptr must be copyable. Otherwise it would be nice for this to be
// move-only.
class NET_EXPORT_PRIVATE StreamBufferDeleter {
 public:
  StreamBufferDeleter() : allocator_(nullptr) {}
  explicit StreamBufferDeleter(QuicBufferAllocator* allocator)
      : allocator_(allocator) {}

  // Deletes |buffer| using |allocator_|.
  void operator()(char* buffer) const;

 private:
  // Not owned; must be valid so long as the buffer stored in the unique_ptr
  // that owns |this| is valid.
  QuicBufferAllocator* allocator_;
};

using UniqueStreamBuffer = std::unique_ptr<char[], StreamBufferDeleter>;

// Allocates memory of size |size| using |allocator| for a QUIC stream buffer.
NET_EXPORT_PRIVATE UniqueStreamBuffer
NewStreamBuffer(QuicBufferAllocator* allocator, size_t size);

struct NET_EXPORT_PRIVATE QuicStreamFrame {
  QuicStreamFrame();
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  base::StringPiece data);
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  QuicPacketLength data_length,
                  UniqueStreamBuffer buffer);
  ~QuicStreamFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicStreamFrame& s);

  QuicStreamId stream_id;
  bool fin;
  QuicPacketLength data_length;
  const char* data_buffer;
  QuicStreamOffset offset;  // Location of this data in the stream.
  // nullptr when the QuicStreamFrame is received, and non-null when sent.
  UniqueStreamBuffer buffer;

 private:
  QuicStreamFrame(QuicStreamId stream_id,
                  bool fin,
                  QuicStreamOffset offset,
                  const char* data_buffer,
                  QuicPacketLength data_length,
                  UniqueStreamBuffer buffer);

  DISALLOW_COPY_AND_ASSIGN(QuicStreamFrame);
};
static_assert(sizeof(QuicStreamFrame) <= 64,
              "Keep the QuicStreamFrame size to a cacheline.");

typedef std::vector<std::pair<QuicPacketNumber, QuicTime>> PacketTimeVector;

struct NET_EXPORT_PRIVATE QuicStopWaitingFrame {
  QuicStopWaitingFrame();
  ~QuicStopWaitingFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicStopWaitingFrame& s);
  // Path which this stop waiting frame belongs to.
  QuicPathId path_id;
  // Entropy hash of all packets up to, but not including, the least unacked
  // packet.
  QuicPacketEntropyHash entropy_hash;
  // The lowest packet we've sent which is unacked, and we expect an ack for.
  QuicPacketNumber least_unacked;
};

// A sequence of packet numbers where each number is unique. Intended to be used
// in a sliding window fashion, where smaller old packet numbers are removed and
// larger new packet numbers are added, with the occasional random access.
class NET_EXPORT_PRIVATE PacketNumberQueue {
 public:
  // TODO(jdorfman): remove const_iterator and change the callers to iterate
  // over the intervals.
  class NET_EXPORT_PRIVATE const_iterator
      : public std::iterator<std::input_iterator_tag,
                             QuicPacketNumber,
                             std::ptrdiff_t,
                             const QuicPacketNumber*,
                             const QuicPacketNumber&> {
   public:
    const_iterator(
        IntervalSet<QuicPacketNumber>::const_iterator interval_set_iter,
        QuicPacketNumber first,
        QuicPacketNumber last);
    const_iterator(const const_iterator& other);
    const_iterator& operator=(const const_iterator& other);
    // TODO(rtenneti): on windows RValue reference gives errors.
    // const_iterator(const_iterator&& other);
    ~const_iterator();

    // TODO(rtenneti): on windows RValue reference gives errors.
    // const_iterator& operator=(const_iterator&& other);
    bool operator!=(const const_iterator& other) const;
    bool operator==(const const_iterator& other) const;
    value_type operator*() const;
    const_iterator& operator++();
    const_iterator operator++(int /* postincrement */);

   private:
    IntervalSet<QuicPacketNumber>::const_iterator interval_set_iter_;
    QuicPacketNumber current_;
    QuicPacketNumber last_;
  };

  PacketNumberQueue();
  PacketNumberQueue(const PacketNumberQueue& other);
  // TODO(rtenneti): on windows RValue reference gives errors.
  // PacketNumberQueue(PacketNumberQueue&& other);
  ~PacketNumberQueue();

  PacketNumberQueue& operator=(const PacketNumberQueue& other);
  // PacketNumberQueue& operator=(PacketNumberQueue&& other);

  // Adds |packet_number| to the set of packets in the queue.
  void Add(QuicPacketNumber packet_number);

  // Adds packets between [lower, higher) to the set of packets in the queue. It
  // is undefined behavior to call this with |higher| < |lower|.
  void Add(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes |packet_number| from the set of packets in the queue.
  void Remove(QuicPacketNumber packet_number);

  // Removes packets numbers between [lower, higher) to the set of packets in
  // the queue. It is undefined behavior to call this with |higher| < |lower|.
  void Remove(QuicPacketNumber lower, QuicPacketNumber higher);

  // Removes packets with values less than |higher| from the set of packets in
  // the queue. Returns true if packets were removed.
  bool RemoveUpTo(QuicPacketNumber higher);

  // Returns true if the queue contains |packet_number|.
  bool Contains(QuicPacketNumber packet_number) const;

  // Returns true if the queue is empty.
  bool Empty() const;

  // Returns the minimum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Min() const;

  // Returns the maximum packet number stored in the queue. It is undefined
  // behavior to call this if the queue is empty.
  QuicPacketNumber Max() const;

  // Returns the number of unique packets stored in the queue. Inefficient; only
  // exposed for testing.
  size_t NumPacketsSlow() const;

  // Returns the number of disjoint packet number intervals contained in the
  // queue.
  size_t NumIntervals() const;

  // Returns the length of last interval.
  QuicPacketNumber LastIntervalLength() const;

  // Returns iterators over the individual packet numbers.
  const_iterator begin() const;
  const_iterator end() const;
  const_iterator lower_bound(QuicPacketNumber packet_number) const;

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const PacketNumberQueue& q);

 private:
  IntervalSet<QuicPacketNumber> packet_number_intervals_;
};

struct NET_EXPORT_PRIVATE QuicAckFrame {
  QuicAckFrame();
  QuicAckFrame(const QuicAckFrame& other);
  ~QuicAckFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicAckFrame& s);

  // The highest packet number we've observed from the peer.
  //
  // In general, this should be the largest packet number we've received.  In
  // the case of truncated acks, we may have to advertise a lower "upper bound"
  // than largest received, to avoid implicitly acking missing packets that
  // don't fit in the missing packet list due to size limitations.  In this
  // case, largest_observed may be a packet which is also in the missing packets
  // list.
  QuicPacketNumber largest_observed;

  // Time elapsed since largest_observed was received until this Ack frame was
  // sent.
  QuicTime::Delta ack_delay_time;

  // Vector of <packet_number, time> for when packets arrived.
  PacketTimeVector received_packet_times;

  // Set of packets.
  PacketNumberQueue packets;

  // Path which this ack belongs to.
  QuicPathId path_id;

  // Entropy hash of all packets up to largest observed not including missing
  // packets.
  QuicPacketEntropyHash entropy_hash;

  // Whether the ack had to be truncated when sent.
  bool is_truncated;

  // If true, |packets| express missing packets. Otherwise, |packets| express
  // received packets.
  bool missing;
};

// True if the packet number is greater than largest_observed or is listed
// as missing.
// Always returns false for packet numbers less than least_unacked.
bool NET_EXPORT_PRIVATE
IsAwaitingPacket(const QuicAckFrame& ack_frame,
                 QuicPacketNumber packet_number,
                 QuicPacketNumber peer_least_packet_awaiting_ack);

// Defines for all types of congestion control algorithms that can be used in
// QUIC. Note that this is separate from the congestion feedback type -
// some congestion control algorithms may use the same feedback type
// (Reno and Cubic are the classic example for that).
enum CongestionControlType {
  kCubic,
  kCubicBytes,
  kReno,
  kRenoBytes,
  kBBR,
};

enum LossDetectionType {
  kNack,          // Used to mimic TCP's loss detection.
  kTime,          // Time based loss detection.
  kAdaptiveTime,  // Adaptive time based loss detection.
};

struct NET_EXPORT_PRIVATE QuicRstStreamFrame {
  QuicRstStreamFrame();
  QuicRstStreamFrame(QuicStreamId stream_id,
                     QuicRstStreamErrorCode error_code,
                     QuicStreamOffset bytes_written);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicRstStreamFrame& r);

  QuicStreamId stream_id;
  QuicRstStreamErrorCode error_code;

  // Used to update flow control windows. On termination of a stream, both
  // endpoints must inform the peer of the number of bytes they have sent on
  // that stream. This can be done through normal termination (data packet with
  // FIN) or through a RST.
  QuicStreamOffset byte_offset;
};

struct NET_EXPORT_PRIVATE QuicConnectionCloseFrame {
  QuicConnectionCloseFrame();

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicConnectionCloseFrame& c);

  QuicErrorCode error_code;
  std::string error_details;
};

struct NET_EXPORT_PRIVATE QuicGoAwayFrame {
  QuicGoAwayFrame();
  QuicGoAwayFrame(QuicErrorCode error_code,
                  QuicStreamId last_good_stream_id,
                  const std::string& reason);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicGoAwayFrame& g);

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
      std::ostream& os,
      const QuicWindowUpdateFrame& w);

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

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicBlockedFrame& b);

  // The stream this frame applies to.  0 is a special case meaning the overall
  // connection rather than a specific stream.
  QuicStreamId stream_id;
};

// The PATH_CLOSE frame is used to explicitly close a path. Both endpoints can
// send a PATH_CLOSE frame to initiate a path termination. A path is considered
// to be closed either a PATH_CLOSE frame is sent or received. An endpoint drops
// receive side of a closed path, and packets with retransmittable frames on a
// closed path are marked as retransmissions which will be transmitted on other
// paths.
struct NET_EXPORT_PRIVATE QuicPathCloseFrame {
  QuicPathCloseFrame() {}
  explicit QuicPathCloseFrame(QuicPathId path_id);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicPathCloseFrame& p);

  QuicPathId path_id;
};

// EncryptionLevel enumerates the stages of encryption that a QUIC connection
// progresses through. When retransmitting a packet, the encryption level needs
// to be specified so that it is retransmitted at a level which the peer can
// understand.
enum EncryptionLevel : int8_t {
  ENCRYPTION_NONE = 0,
  ENCRYPTION_INITIAL = 1,
  ENCRYPTION_FORWARD_SECURE = 2,

  NUM_ENCRYPTION_LEVELS,
};

enum PeerAddressChangeType {
  // IP address and port remain unchanged.
  NO_CHANGE,
  // Port changed, but IP address remains unchanged.
  PORT_CHANGE,
  // IPv4 address changed, but within the /24 subnet (port may have changed.)
  IPV4_SUBNET_CHANGE,
  // IP address change from an IPv4 to an IPv6 address (port may have changed.)
  IPV4_TO_IPV6_CHANGE,
  // IP address change from an IPv6 to an IPv4 address (port may have changed.)
  IPV6_TO_IPV4_CHANGE,
  // IP address change from an IPv6 to an IPv6 address (port may have changed.)
  IPV6_TO_IPV6_CHANGE,
  // All other peer address changes.
  UNSPECIFIED_CHANGE,
};

struct NET_EXPORT_PRIVATE QuicFrame {
  QuicFrame();
  explicit QuicFrame(QuicPaddingFrame padding_frame);
  explicit QuicFrame(QuicMtuDiscoveryFrame frame);
  explicit QuicFrame(QuicPingFrame frame);

  explicit QuicFrame(QuicStreamFrame* stream_frame);
  explicit QuicFrame(QuicAckFrame* frame);
  explicit QuicFrame(QuicRstStreamFrame* frame);
  explicit QuicFrame(QuicConnectionCloseFrame* frame);
  explicit QuicFrame(QuicStopWaitingFrame* frame);
  explicit QuicFrame(QuicGoAwayFrame* frame);
  explicit QuicFrame(QuicWindowUpdateFrame* frame);
  explicit QuicFrame(QuicBlockedFrame* frame);
  explicit QuicFrame(QuicPathCloseFrame* frame);

  NET_EXPORT_PRIVATE friend std::ostream& operator<<(std::ostream& os,
                                                     const QuicFrame& frame);

  QuicFrameType type;
  union {
    // Frames smaller than a pointer are inline.
    QuicPaddingFrame padding_frame;
    QuicMtuDiscoveryFrame mtu_discovery_frame;
    QuicPingFrame ping_frame;

    // Frames larger than a pointer.
    QuicStreamFrame* stream_frame;
    QuicAckFrame* ack_frame;
    QuicStopWaitingFrame* stop_waiting_frame;
    QuicRstStreamFrame* rst_stream_frame;
    QuicConnectionCloseFrame* connection_close_frame;
    QuicGoAwayFrame* goaway_frame;
    QuicWindowUpdateFrame* window_update_frame;
    QuicBlockedFrame* blocked_frame;
    QuicPathCloseFrame* path_close_frame;
  };
};
// QuicFrameType consumes 8 bytes with padding.
static_assert(sizeof(QuicFrame) <= 16,
              "Frames larger than 8 bytes should be referenced by pointer.");

typedef std::vector<QuicFrame> QuicFrames;

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
  bool owns_buffer() const { return owns_buffer_; }

 private:
  const char* buffer_;
  size_t length_;
  bool owns_buffer_;

  DISALLOW_COPY_AND_ASSIGN(QuicData);
};

class NET_EXPORT_PRIVATE QuicPacket : public QuicData {
 public:
  // TODO(fayang): 4 fields from public header are passed in as arguments.
  // Consider to add a convenience method which directly accepts the entire
  // public header.
  QuicPacket(char* buffer,
             size_t length,
             bool owns_buffer,
             QuicConnectionIdLength connection_id_length,
             bool includes_version,
             bool includes_path_id,
             bool includes_diversification_nonce,
             QuicPacketNumberLength packet_number_length);

  base::StringPiece AssociatedData(QuicVersion version) const;
  base::StringPiece Plaintext(QuicVersion version) const;

  char* mutable_data() { return buffer_; }

 private:
  char* buffer_;
  const QuicConnectionIdLength connection_id_length_;
  const bool includes_version_;
  const bool includes_path_id_;
  const bool includes_diversification_nonce_;
  const QuicPacketNumberLength packet_number_length_;

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
      std::ostream& os,
      const QuicEncryptedPacket& s);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicEncryptedPacket);
};

// A received encrypted QUIC packet, with a recorded time of receipt.
class NET_EXPORT_PRIVATE QuicReceivedPacket : public QuicEncryptedPacket {
 public:
  QuicReceivedPacket(const char* buffer, size_t length, QuicTime receipt_time);
  QuicReceivedPacket(char* buffer,
                     size_t length,
                     QuicTime receipt_time,
                     bool owns_buffer);

  // Clones the packet into a new packet which owns the buffer.
  QuicReceivedPacket* Clone() const;

  // Returns the time at which the packet was received.
  QuicTime receipt_time() const { return receipt_time_; }

  // By default, gtest prints the raw bytes of an object. The bool data
  // member (in the base class QuicData) causes this object to have padding
  // bytes, which causes the default gtest object printer to read
  // uninitialize memory. So we need to teach gtest how to print this object.
  NET_EXPORT_PRIVATE friend std::ostream& operator<<(
      std::ostream& os,
      const QuicReceivedPacket& s);

 private:
  const QuicTime receipt_time_;

  DISALLOW_COPY_AND_ASSIGN(QuicReceivedPacket);
};

// Pure virtual class to listen for packet acknowledgements.
class NET_EXPORT_PRIVATE QuicAckListenerInterface
    : public base::RefCounted<QuicAckListenerInterface> {
 public:
  QuicAckListenerInterface() {}

  // Called when a packet is acked.  Called once per packet.
  // |acked_bytes| is the number of data bytes acked.
  virtual void OnPacketAcked(int acked_bytes,
                             QuicTime::Delta ack_delay_time) = 0;

  // Called when a packet is retransmitted.  Called once per packet.
  // |retransmitted_bytes| is the number of data bytes retransmitted.
  virtual void OnPacketRetransmitted(int retransmitted_bytes) = 0;

 protected:
  friend class base::RefCounted<QuicAckListenerInterface>;

  // Delegates are ref counted.
  virtual ~QuicAckListenerInterface() {}
};

// Pure virtual class to close connection on unrecoverable errors.
class NET_EXPORT_PRIVATE QuicConnectionCloseDelegateInterface {
 public:
  virtual ~QuicConnectionCloseDelegateInterface() {}

  // Called when an unrecoverable error is encountered.
  virtual void OnUnrecoverableError(QuicErrorCode error,
                                    const std::string& error_details,
                                    ConnectionCloseSource source) = 0;
};

struct NET_EXPORT_PRIVATE AckListenerWrapper {
  AckListenerWrapper(QuicAckListenerInterface* listener,
                     QuicPacketLength data_length);
  AckListenerWrapper(const AckListenerWrapper& other);
  ~AckListenerWrapper();

  scoped_refptr<QuicAckListenerInterface> ack_listener;
  QuicPacketLength length;
};

struct NET_EXPORT_PRIVATE SerializedPacket {
  SerializedPacket(QuicPathId path_id,
                   QuicPacketNumber packet_number,
                   QuicPacketNumberLength packet_number_length,
                   const char* encrypted_buffer,
                   QuicPacketLength encrypted_length,
                   QuicPacketEntropyHash entropy_hash,
                   bool has_ack,
                   bool has_stop_waiting);
  SerializedPacket(const SerializedPacket& other);
  ~SerializedPacket();

  // Not owned.
  const char* encrypted_buffer;
  QuicPacketLength encrypted_length;
  QuicFrames retransmittable_frames;
  IsHandshake has_crypto_handshake;
  // -1: full padding to the end of a max-sized packet
  //  0: no padding
  //  otherwise: only pad up to num_padding_bytes bytes
  int16_t num_padding_bytes;
  QuicPathId path_id;
  QuicPacketNumber packet_number;
  QuicPacketNumberLength packet_number_length;
  EncryptionLevel encryption_level;
  QuicPacketEntropyHash entropy_hash;
  bool has_ack;
  bool has_stop_waiting;
  TransmissionType transmission_type;
  QuicPathId original_path_id;
  QuicPacketNumber original_packet_number;

  // Optional notifiers which will be informed when this packet has been ACKed.
  std::list<AckListenerWrapper> listeners;
};

struct NET_EXPORT_PRIVATE TransmissionInfo {
  // Used by STL when assigning into a map.
  TransmissionInfo();

  // Constructs a Transmission with a new all_transmissions set
  // containing |packet_number|.
  TransmissionInfo(EncryptionLevel level,
                   QuicPacketNumberLength packet_number_length,
                   TransmissionType transmission_type,
                   QuicTime sent_time,
                   QuicPacketLength bytes_sent,
                   bool has_crypto_handshake,
                   int num_padding_bytes);

  TransmissionInfo(const TransmissionInfo& other);

  ~TransmissionInfo();

  QuicFrames retransmittable_frames;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
  QuicPacketLength bytes_sent;
  QuicTime sent_time;
  // Reason why this packet was transmitted.
  TransmissionType transmission_type;
  // In flight packets have not been abandoned or lost.
  bool in_flight;
  // True if the packet can never be acked, so it can be removed.  Occurs when
  // a packet is never sent, after it is acknowledged once, or if it's a crypto
  // packet we never expect to receive an ack for.
  bool is_unackable;
  // True if the packet contains stream data from the crypto stream.
  bool has_crypto_handshake;
  // Non-zero if the packet needs padding if it's retransmitted.
  int16_t num_padding_bytes;
  // Stores the packet number of the next retransmission of this packet.
  // Zero if the packet has not been retransmitted.
  QuicPacketNumber retransmission;
  // Non-empty if there is a listener for this packet.
  std::list<AckListenerWrapper> ack_listeners;
};

// Struct to store the pending retransmission information.
struct PendingRetransmission {
  PendingRetransmission(QuicPathId path_id,
                        QuicPacketNumber packet_number,
                        TransmissionType transmission_type,
                        const QuicFrames& retransmittable_frames,
                        bool has_crypto_handshake,
                        int num_padding_bytes,
                        EncryptionLevel encryption_level,
                        QuicPacketNumberLength packet_number_length)
      : packet_number(packet_number),
        retransmittable_frames(retransmittable_frames),
        transmission_type(transmission_type),
        path_id(path_id),
        has_crypto_handshake(has_crypto_handshake),
        num_padding_bytes(num_padding_bytes),
        encryption_level(encryption_level),
        packet_number_length(packet_number_length) {}

  QuicPacketNumber packet_number;
  const QuicFrames& retransmittable_frames;
  TransmissionType transmission_type;
  QuicPathId path_id;
  bool has_crypto_handshake;
  int num_padding_bytes;
  EncryptionLevel encryption_level;
  QuicPacketNumberLength packet_number_length;
};

// Convenience wrapper to wrap an iovec array and the total length, which must
// be less than or equal to the actual total length of the iovecs.
struct NET_EXPORT_PRIVATE QuicIOVector {
  QuicIOVector(const struct iovec* iov, int iov_count, size_t total_length)
      : iov(iov), iov_count(iov_count), total_length(total_length) {}

  const struct iovec* iov;
  const int iov_count;
  const size_t total_length;
};

}  // namespace net

#endif  // NET_QUIC_QUIC_PROTOCOL_H_
