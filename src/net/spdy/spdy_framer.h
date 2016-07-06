// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FRAMER_H_
#define NET_SPDY_SPDY_FRAMER_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "base/strings/string_piece.h"
#include "base/sys_byteorder.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_decoder.h"
#include "net/spdy/hpack/hpack_decoder_interface.h"
#include "net/spdy/hpack/hpack_encoder.h"
#include "net/spdy/spdy_alt_svc_wire_format.h"
#include "net/spdy/spdy_flags.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_headers_block_parser.h"
#include "net/spdy/spdy_headers_handler_interface.h"
#include "net/spdy/spdy_protocol.h"

typedef struct z_stream_s z_stream;  // Forward declaration for zlib.

namespace net {

class HttpProxyClientSocketPoolTest;
class HttpNetworkLayer;
class HttpNetworkTransactionTest;
class SpdyHttpStreamTest;
class SpdyNetworkTransactionTest;
class SpdyProxyClientSocketTest;
class SpdySessionTest;
class SpdyStreamTest;

class SpdyFramer;
class SpdyFrameBuilder;
class SpdyFramerDecoderAdapter;

namespace test {

class TestSpdyVisitor;
class SpdyFramerPeer;

}  // namespace test

// A datastructure for holding the ID and flag fields for SETTINGS.
// Conveniently handles converstion to/from wire format.
class NET_EXPORT_PRIVATE SettingsFlagsAndId {
 public:
  static SettingsFlagsAndId FromWireFormat(SpdyMajorVersion version,
                                           uint32_t wire);

  SettingsFlagsAndId() : flags_(0), id_(0) {}

  // TODO(hkhalil): restrict to enums instead of free-form ints.
  SettingsFlagsAndId(uint8_t flags, uint32_t id);

  uint32_t GetWireFormat(SpdyMajorVersion version) const;

  uint32_t id() const { return id_; }
  uint8_t flags() const { return flags_; }

 private:
  uint8_t flags_;
  uint32_t id_;
};

// SettingsMap has unique (flags, value) pair for given SpdySettingsIds ID.
typedef std::pair<SpdySettingsFlags, uint32_t> SettingsFlagsAndValue;
typedef std::map<SpdySettingsIds, SettingsFlagsAndValue> SettingsMap;

// SpdyFramerVisitorInterface is a set of callbacks for the SpdyFramer.
// Implement this interface to receive event callbacks as frames are
// decoded from the framer.
//
// Control frames that contain SPDY header blocks (SYN_STREAM, SYN_REPLY,
// HEADER, and PUSH_PROMISE) are processed in fashion that allows the
// decompressed header block to be delivered in chunks to the visitor.
// The following steps are followed:
//   1. OnSynStream, OnSynReply, OnHeaders, or OnPushPromise is called.
//   2. Repeated: OnControlFrameHeaderData is called with chunks of the
//      decompressed header block. In each call the len parameter is greater
//      than zero.
//   3. OnControlFrameHeaderData is called with len set to zero, indicating
//      that the full header block has been delivered for the control frame.
// During step 2 the visitor may return false, indicating that the chunk of
// header data could not be handled by the visitor (typically this indicates
// resource exhaustion). If this occurs the framer will discontinue
// delivering chunks to the visitor, set a SPDY_CONTROL_PAYLOAD_TOO_LARGE
// error, and clean up appropriately. Note that this will cause the header
// decompressor to lose synchronization with the sender's header compressor,
// making the SPDY session unusable for future work. The visitor's OnError
// function should deal with this condition by closing the SPDY connection.
class NET_EXPORT_PRIVATE SpdyFramerVisitorInterface {
 public:
  virtual ~SpdyFramerVisitorInterface() {}

  // Called if an error is detected in the SpdySerializedFrame protocol.
  virtual void OnError(SpdyFramer* framer) = 0;

  // Called when a data frame header is received. The frame's data
  // payload will be provided via subsequent calls to
  // OnStreamFrameData().
  virtual void OnDataFrameHeader(SpdyStreamId stream_id,
                                 size_t length,
                                 bool fin) = 0;

  // Called when data is received.
  // |stream_id| The stream receiving data.
  // |data| A buffer containing the data received.
  // |len| The length of the data buffer.
  virtual void OnStreamFrameData(SpdyStreamId stream_id,
                                 const char* data,
                                 size_t len) = 0;

  // Called when the other side has finished sending data on this stream.
  // |stream_id| The stream that was receivin data.
  virtual void OnStreamEnd(SpdyStreamId stream_id) = 0;

  // Called when padding is received (padding length field or padding octets).
  // |stream_id| The stream receiving data.
  // |len| The number of padding octets.
  virtual void OnStreamPadding(SpdyStreamId stream_id, size_t len) = 0;

  // Called just before processing the payload of a frame containing header
  // data. Should return an implementation of SpdyHeadersHandlerInterface that
  // will receive headers for stream |stream_id|. The caller will not take
  // ownership of the headers handler. The same instance should remain live
  // and be returned for all header frames comprising a logical header block
  // (i.e. until OnHeaderFrameEnd() is called with end_headers == true).
  virtual SpdyHeadersHandlerInterface* OnHeaderFrameStart(
      SpdyStreamId stream_id) = 0;

  // Called after processing the payload of a frame containing header data.
  // |end_headers| is true if there will not be any subsequent CONTINUATION
  // frames.
  virtual void OnHeaderFrameEnd(SpdyStreamId stream_id, bool end_headers) = 0;

  // Called when a chunk of header data is available. This is called
  // after OnSynStream, OnSynReply, OnHeaders(), or OnPushPromise.
  // |stream_id| The stream receiving the header data.
  // |header_data| A buffer containing the header data chunk received.
  // |len| The length of the header data buffer. A length of zero indicates
  //       that the header data block has been completely sent.
  // When this function returns true the visitor indicates that it accepted
  // all of the data. Returning false indicates that that an unrecoverable
  // error has occurred, such as bad header data or resource exhaustion.
  virtual bool OnControlFrameHeaderData(SpdyStreamId stream_id,
                                        const char* header_data,
                                        size_t len) = 0;

  // Called when a SYN_STREAM frame is received.
  // Note that header block data is not included. See
  // OnControlFrameHeaderData().
  virtual void OnSynStream(SpdyStreamId stream_id,
                           SpdyStreamId associated_stream_id,
                           SpdyPriority priority,
                           bool fin,
                           bool unidirectional) = 0;

  // Called when a SYN_REPLY frame is received.
  // Note that header block data is not included. See
  // OnControlFrameHeaderData().
  virtual void OnSynReply(SpdyStreamId stream_id, bool fin) = 0;

  // Called when a RST_STREAM frame has been parsed.
  virtual void OnRstStream(SpdyStreamId stream_id,
                           SpdyRstStreamStatus status) = 0;

  // Called when a SETTINGS frame is received.
  // |clear_persisted| True if the respective flag is set on the SETTINGS frame.
  virtual void OnSettings(bool clear_persisted) {}

  // Called when a complete setting within a SETTINGS frame has been parsed and
  // validated.
  virtual void OnSetting(SpdySettingsIds id, uint8_t flags, uint32_t value) = 0;

  // Called when a SETTINGS frame is received with the ACK flag set.
  virtual void OnSettingsAck() {}

  // Called before and after parsing SETTINGS id and value tuples.
  virtual void OnSettingsEnd() = 0;

  // Called when a PING frame has been parsed.
  virtual void OnPing(SpdyPingId unique_id, bool is_ack) = 0;

  // Called when a GOAWAY frame has been parsed.
  virtual void OnGoAway(SpdyStreamId last_accepted_stream_id,
                        SpdyGoAwayStatus status) = 0;

  // Called when a HEADERS frame is received.
  // Note that header block data is not included. See
  // OnControlFrameHeaderData().
  // |stream_id| The stream receiving the header.
  // |has_priority| Whether or not the headers frame included a priority value,
  //     and, if protocol version == HTTP2, stream dependency info.
  // |weight| If |has_priority| is true, then weight (in the range [1, 256])
  //     for the receiving stream, otherwise 0.
  // |parent_stream_id| If |has_priority| is true and protocol
  //     version == HTTP2, the parent stream of the receiving stream, else 0.
  // |exclusive| If |has_priority| is true and protocol
  //     version == HTTP2, the exclusivity of dependence on the parent stream,
  //     else false.
  // |fin| Whether FIN flag is set in frame headers.
  // |end| False if HEADERs frame is to be followed by a CONTINUATION frame,
  //     or true if not.
  virtual void OnHeaders(SpdyStreamId stream_id,
                         bool has_priority,
                         int weight,
                         SpdyStreamId parent_stream_id,
                         bool exclusive,
                         bool fin,
                         bool end) = 0;

  // Called when a WINDOW_UPDATE frame has been parsed.
  virtual void OnWindowUpdate(SpdyStreamId stream_id,
                              int delta_window_size) = 0;

  // Called when a goaway frame opaque data is available.
  // |goaway_data| A buffer containing the opaque GOAWAY data chunk received.
  // |len| The length of the header data buffer. A length of zero indicates
  //       that the header data block has been completely sent.
  // When this function returns true the visitor indicates that it accepted
  // all of the data. Returning false indicates that that an error has
  // occurred while processing the data. Default implementation returns true.
  virtual bool OnGoAwayFrameData(const char* goaway_data, size_t len);

  // Called when rst_stream frame opaque data is available.
  // |rst_stream_data| A buffer containing the opaque RST_STREAM
  // data chunk received.
  // |len| The length of the header data buffer. A length of zero indicates
  //       that the opaque data has been completely sent.
  // When this function returns true the visitor indicates that it accepted
  // all of the data. Returning false indicates that that an error has
  // occurred while processing the data. Default implementation returns true.
  virtual bool OnRstStreamFrameData(const char* rst_stream_data, size_t len);

  // Called when a BLOCKED frame has been parsed.
  virtual void OnBlocked(SpdyStreamId stream_id) {}

  // Called when a PUSH_PROMISE frame is received.
  // Note that header block data is not included. See
  // OnControlFrameHeaderData().
  virtual void OnPushPromise(SpdyStreamId stream_id,
                             SpdyStreamId promised_stream_id,
                             bool end) = 0;

  // Called when a CONTINUATION frame is received.
  // Note that header block data is not included. See
  // OnControlFrameHeaderData().
  virtual void OnContinuation(SpdyStreamId stream_id, bool end) = 0;

  // Called when an ALTSVC frame has been parsed.
  virtual void OnAltSvc(
      SpdyStreamId stream_id,
      base::StringPiece origin,
      const SpdyAltSvcWireFormat::AlternativeServiceVector& altsvc_vector) {}

  // Called when a PRIORITY frame is received.
  // |stream_id| The stream to update the priority of.
  // |parent_stream_id| The parent stream of |stream_id|.
  // |weight| Stream weight, in the range [1, 256].
  // |exclusive| Whether |stream_id| should be an only child of
  //     |parent_stream_id|.
  virtual void OnPriority(SpdyStreamId stream_id,
                          SpdyStreamId parent_stream_id,
                          int weight,
                          bool exclusive) {}

  // Called when a frame type we don't recognize is received.
  // Return true if this appears to be a valid extension frame, false otherwise.
  // We distinguish between extension frames and nonsense by checking
  // whether the stream id is valid.
  virtual bool OnUnknownFrame(SpdyStreamId stream_id, int frame_type) = 0;
};

// Optionally, and in addition to SpdyFramerVisitorInterface, a class supporting
// SpdyFramerDebugVisitorInterface may be used in conjunction with SpdyFramer in
// order to extract debug/internal information about the SpdyFramer as it
// operates.
//
// Most SPDY implementations need not bother with this interface at all.
class NET_EXPORT_PRIVATE SpdyFramerDebugVisitorInterface {
 public:
  virtual ~SpdyFramerDebugVisitorInterface() {}

  // Called after compressing a frame with a payload of
  // a list of name-value pairs.
  // |payload_len| is the uncompressed payload size.
  // |frame_len| is the compressed frame size.
  virtual void OnSendCompressedFrame(SpdyStreamId stream_id,
                                     SpdyFrameType type,
                                     size_t payload_len,
                                     size_t frame_len) {}

  // Called when a frame containing a compressed payload of
  // name-value pairs is received.
  // |frame_len| is the compressed frame size.
  virtual void OnReceiveCompressedFrame(SpdyStreamId stream_id,
                                        SpdyFrameType type,
                                        size_t frame_len) {}
};

class NET_EXPORT_PRIVATE SpdyFramer {
 public:
  // SPDY states.
  // TODO(mbelshe): Can we move these into the implementation
  //                and avoid exposing through the header.  (Needed for test)
  enum SpdyState {
    SPDY_ERROR,
    SPDY_READY_FOR_FRAME,  // Framer is ready for reading the next frame.
    SPDY_FRAME_COMPLETE,  // Framer has finished reading a frame, need to reset.
    SPDY_READING_COMMON_HEADER,
    SPDY_CONTROL_FRAME_PAYLOAD,
    SPDY_READ_DATA_FRAME_PADDING_LENGTH,
    SPDY_CONSUME_PADDING,
    SPDY_IGNORE_REMAINING_PAYLOAD,
    SPDY_FORWARD_STREAM_FRAME,
    SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK,
    SPDY_CONTROL_FRAME_HEADER_BLOCK,
    SPDY_GOAWAY_FRAME_PAYLOAD,
    SPDY_RST_STREAM_FRAME_PAYLOAD,
    SPDY_SETTINGS_FRAME_HEADER,
    SPDY_SETTINGS_FRAME_PAYLOAD,
    SPDY_ALTSVC_FRAME_PAYLOAD,
  };

  // SPDY error codes.
  enum SpdyError {
    SPDY_NO_ERROR,
    SPDY_INVALID_STREAM_ID,            // Stream ID is invalid
    SPDY_INVALID_CONTROL_FRAME,        // Control frame is mal-formatted.
    SPDY_CONTROL_PAYLOAD_TOO_LARGE,    // Control frame payload was too large.
    SPDY_ZLIB_INIT_FAILURE,            // The Zlib library could not initialize.
    SPDY_UNSUPPORTED_VERSION,          // Control frame has unsupported version.
    SPDY_DECOMPRESS_FAILURE,           // There was an error decompressing.
    SPDY_COMPRESS_FAILURE,             // There was an error compressing.
    SPDY_GOAWAY_FRAME_CORRUPT,         // GOAWAY frame could not be parsed.
    SPDY_RST_STREAM_FRAME_CORRUPT,     // RST_STREAM frame could not be parsed.
    SPDY_INVALID_PADDING,              // HEADERS or DATA frame padding invalid
    SPDY_INVALID_DATA_FRAME_FLAGS,     // Data frame has invalid flags.
    SPDY_INVALID_CONTROL_FRAME_FLAGS,  // Control frame has invalid flags.
    SPDY_UNEXPECTED_FRAME,             // Frame received out of order.
    SPDY_INTERNAL_FRAMER_ERROR,        // SpdyFramer was used incorrectly.
    SPDY_INVALID_CONTROL_FRAME_SIZE,   // Control frame not sized to spec
    SPDY_OVERSIZED_PAYLOAD,            // Payload size was too large

    LAST_ERROR,  // Must be the last entry in the enum.
  };

  // Constant for invalid (or unknown) stream IDs.
  static const SpdyStreamId kInvalidStream;

  // The maximum size of header data chunks delivered to the framer visitor
  // through OnControlFrameHeaderData. (It is exposed here for unit test
  // purposes.)
  static const size_t kHeaderDataChunkMaxSize;

  void SerializeHeaderBlockWithoutCompression(
      SpdyFrameBuilder* builder,
      const SpdyHeaderBlock& header_block) const;

  // Retrieve serialized length of SpdyHeaderBlock.
  // TODO(hkhalil): Remove, or move to quic code.
  static size_t GetSerializedLength(
      const SpdyMajorVersion spdy_version,
      const SpdyHeaderBlock* headers);

  // Create a new Framer, provided a SPDY version.
  explicit SpdyFramer(SpdyMajorVersion version);

  // Used recursively from the above constructor in order to support
  // instantiating a SpdyFramerDecoderAdapter selected via flags.
  SpdyFramer(SpdyMajorVersion version, bool choose_decoder);

  virtual ~SpdyFramer();

  // Set callbacks to be called from the framer.  A visitor must be set, or
  // else the framer will likely crash.  It is acceptable for the visitor
  // to do nothing.  If this is called multiple times, only the last visitor
  // will be used.
  void set_visitor(SpdyFramerVisitorInterface* visitor);

  // Set debug callbacks to be called from the framer. The debug visitor is
  // completely optional and need not be set in order for normal operation.
  // If this is called multiple times, only the last visitor will be used.
  void set_debug_visitor(SpdyFramerDebugVisitorInterface* debug_visitor);

  // Sets whether or not ProcessInput returns after finishing a frame, or
  // continues processing additional frames. Normally ProcessInput processes
  // all input, but this method enables the caller (and visitor) to work with
  // a single frame at a time (or that portion of the frame which is provided
  // as input). Reset() does not change the value of this flag.
  void set_process_single_input_frame(bool v);

  // Pass data into the framer for parsing.
  // Returns the number of bytes consumed. It is safe to pass more bytes in
  // than may be consumed.
  size_t ProcessInput(const char* data, size_t len);

  // Resets the framer state after a frame has been successfully decoded.
  // TODO(mbelshe): can we make this private?
  void Reset();

  // Check the state of the framer.
  SpdyError error_code() const;
  SpdyState state() const;
  bool HasError() const { return state() == SPDY_ERROR; }

  // Given a buffer containing a decompressed header block in SPDY
  // serialized format, parse out a SpdyHeaderBlock, putting the results
  // in the given header block.
  // Returns true if successfully parsed, false otherwise.
  bool ParseHeaderBlockInBuffer(const char* header_data,
                                size_t header_length,
                                SpdyHeaderBlock* block) const;

  // Serialize a data frame.
  SpdySerializedFrame SerializeData(const SpdyDataIR& data) const;
  // Serializes the data frame header and optionally padding length fields,
  // excluding actual data payload and padding.
  SpdySerializedFrame SerializeDataFrameHeaderWithPaddingLengthField(
      const SpdyDataIR& data) const;

  // Serializes a SYN_STREAM frame.
  SpdySerializedFrame SerializeSynStream(const SpdySynStreamIR& syn_stream);

  // Serialize a SYN_REPLY frame.
  SpdySerializedFrame SerializeSynReply(const SpdySynReplyIR& syn_reply);

  SpdySerializedFrame SerializeRstStream(
      const SpdyRstStreamIR& rst_stream) const;

  // Serializes a SETTINGS frame. The SETTINGS frame is
  // used to communicate name/value pairs relevant to the communication channel.
  SpdySerializedFrame SerializeSettings(const SpdySettingsIR& settings) const;

  // Serializes a PING frame. The unique_id is used to
  // identify the ping request/response.
  SpdySerializedFrame SerializePing(const SpdyPingIR& ping) const;

  // Serializes a GOAWAY frame. The GOAWAY frame is used
  // prior to the shutting down of the TCP connection, and includes the
  // stream_id of the last stream the sender of the frame is willing to process
  // to completion.
  SpdySerializedFrame SerializeGoAway(const SpdyGoAwayIR& goaway) const;

  // Serializes a HEADERS frame. The HEADERS frame is used
  // for sending additional headers outside of a SYN_STREAM/SYN_REPLY.
  SpdySerializedFrame SerializeHeaders(const SpdyHeadersIR& headers);

  // Serializes a WINDOW_UPDATE frame. The WINDOW_UPDATE
  // frame is used to implement per stream flow control in SPDY.
  SpdySerializedFrame SerializeWindowUpdate(
      const SpdyWindowUpdateIR& window_update) const;

  // Serializes a BLOCKED frame. The BLOCKED frame is used to
  // indicate to the remote endpoint that this endpoint believes itself to be
  // flow-control blocked but otherwise ready to send data. The BLOCKED frame
  // is purely advisory and optional.
  SpdySerializedFrame SerializeBlocked(const SpdyBlockedIR& blocked) const;

  // Serializes a PUSH_PROMISE frame. The PUSH_PROMISE frame is used
  // to inform the client that it will be receiving an additional stream
  // in response to the original request. The frame includes synthesized
  // headers to explain the upcoming data.
  SpdySerializedFrame SerializePushPromise(
      const SpdyPushPromiseIR& push_promise);

  // Serializes a CONTINUATION frame. The CONTINUATION frame is used
  // to continue a sequence of header block fragments.
  // TODO(jgraettinger): This implementation is incorrect. The continuation
  // frame continues a previously-begun HPACK encoding; it doesn't begin a
  // new one. Figure out whether it makes sense to keep SerializeContinuation().
  SpdySerializedFrame SerializeContinuation(
      const SpdyContinuationIR& continuation);

  // Serializes an ALTSVC frame. The ALTSVC frame advertises the
  // availability of an alternative service to the client.
  SpdySerializedFrame SerializeAltSvc(const SpdyAltSvcIR& altsvc);

  // Serializes a PRIORITY frame. The PRIORITY frame advises a change in
  // the relative priority of the given stream.
  SpdySerializedFrame SerializePriority(const SpdyPriorityIR& priority) const;

  // Serialize a frame of unknown type.
  SpdySerializedFrame SerializeFrame(const SpdyFrameIR& frame);

  // NOTES about frame compression.
  // We want spdy to compress headers across the entire session.  As long as
  // the session is over TCP, frames are sent serially.  The client & server
  // can each compress frames in the same order and then compress them in that
  // order, and the remote can do the reverse.  However, we ultimately want
  // the creation of frames to be less sensitive to order so that they can be
  // placed over a UDP based protocol and yet still benefit from some
  // compression.  We don't know of any good compression protocol which does
  // not build its state in a serial (stream based) manner....  For now, we're
  // using zlib anyway.

  // For ease of testing and experimentation we can tweak compression on/off.
  void set_enable_compression(bool value) {
    enable_compression_ = value;
  }

  // Used only in log messages.
  void set_display_protocol(const std::string& protocol) {
    display_protocol_ = protocol;
  }

  void set_max_decode_buffer_size_bytes(size_t max_decode_buffer_size_bytes) {
    GetHpackDecoder()->set_max_decode_buffer_size_bytes(
        max_decode_buffer_size_bytes);
  }

  void set_recv_frame_size_limit(size_t recv_frame_size_limit) {
    recv_frame_size_limit_ = recv_frame_size_limit;
  }

  void SetDecoderHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor);

  void SetEncoderHeaderTableDebugVisitor(
      std::unique_ptr<HpackHeaderTable::DebugVisitorInterface> visitor);

  // Returns the (minimum) size of frames (sans variable-length portions).
  size_t GetDataFrameMinimumSize() const;
  size_t GetControlFrameHeaderSize() const;
  size_t GetSynStreamMinimumSize() const;
  size_t GetSynReplyMinimumSize() const;
  size_t GetRstStreamMinimumSize() const;
  size_t GetSettingsMinimumSize() const;
  size_t GetPingSize() const;
  size_t GetGoAwayMinimumSize() const;
  size_t GetHeadersMinimumSize() const;
  size_t GetWindowUpdateSize() const;
  size_t GetBlockedSize() const;
  size_t GetPushPromiseMinimumSize() const;
  size_t GetContinuationMinimumSize() const;
  size_t GetAltSvcMinimumSize() const;
  size_t GetPrioritySize() const;

  // Returns the minimum size a frame can be (data or control).
  size_t GetFrameMinimumSize() const;

  // Returns the maximum size a frame can be (data or control).
  size_t GetFrameMaximumSize() const;

  // Returns the maximum payload size of a DATA frame.
  size_t GetDataFrameMaximumPayload() const;

  // Returns the prefix length for the given frame type.
  size_t GetPrefixLength(SpdyFrameType type) const;

  // For debugging.
  static const char* StateToString(int state);
  static const char* ErrorCodeToString(int error_code);
  static const char* StatusCodeToString(int status_code);
  static const char* FrameTypeToString(SpdyFrameType type);

  SpdyMajorVersion protocol_version() const { return protocol_version_; }

  // Did the most recent frame header appear to be an HTTP/1.x (or earlier)
  // response (i.e. start with "HTTP/")?
  bool probable_http_response() const;

  SpdyPriority GetLowestPriority() const { return kV3LowestPriority; }

  SpdyPriority GetHighestPriority() const { return kV3HighestPriority; }

  // Deliver the given control frame's compressed headers block to the visitor
  // in decompressed form, in chunks. Returns true if the visitor has
  // accepted all of the chunks.
  bool IncrementallyDecompressControlFrameHeaderData(
      SpdyStreamId stream_id,
      const char* data,
      size_t len);

  // Updates the maximum size of the header encoder compression table.
  void UpdateHeaderEncoderTableSize(uint32_t value);

  // Returns the maximum size of the header encoder compression table.
  size_t header_encoder_table_size() const;

 protected:
  friend class BufferedSpdyFramer;
  friend class HttpNetworkLayer;  // This is temporary for the server.
  friend class HttpNetworkTransactionTest;
  friend class HttpProxyClientSocketPoolTest;
  friend class SpdyHttpStreamTest;
  friend class SpdyNetworkTransactionTest;
  friend class SpdyProxyClientSocketTest;
  friend class SpdySessionTest;
  friend class SpdyStreamTest;
  friend class test::TestSpdyVisitor;
  friend class test::SpdyFramerPeer;

 private:
  class CharBuffer {
   public:
    explicit CharBuffer(size_t capacity);
    ~CharBuffer();

    void CopyFrom(const char* data, size_t size);
    void Rewind();

    const char* data() const { return buffer_.get(); }
    size_t len() const { return len_; }

   private:
    std::unique_ptr<char[]> buffer_;
    size_t capacity_;
    size_t len_;
  };

  // Scratch space necessary for processing SETTINGS frames.
  struct SpdySettingsScratch {
    SpdySettingsScratch();
    void Reset();

    // Buffer contains up to one complete key/value pair.
    CharBuffer buffer;

    // The ID of the last setting that was processed in the current SETTINGS
    // frame. Used for detecting out-of-order or duplicate keys within a
    // settings frame. Set to -1 before first key/value pair is processed.
    int last_setting_id;
  };

  // Internal breakouts from ProcessInput. Each returns the number of bytes
  // consumed from the data.
  size_t ProcessCommonHeader(const char* data, size_t len);
  size_t ProcessControlFramePayload(const char* data, size_t len);
  size_t ProcessControlFrameBeforeHeaderBlock(const char* data, size_t len);
  // HPACK data is re-encoded as SPDY3 and re-entrantly delivered through
  // |ProcessControlFrameHeaderBlock()|. |is_hpack_header_block| controls
  // whether data is treated as HPACK- vs SPDY3-encoded.
  size_t ProcessControlFrameHeaderBlock(const char* data,
                                        size_t len,
                                        bool is_hpack_header_block);
  size_t ProcessDataFramePaddingLength(const char* data, size_t len);
  size_t ProcessFramePadding(const char* data, size_t len);
  size_t ProcessDataFramePayload(const char* data, size_t len);
  size_t ProcessGoAwayFramePayload(const char* data, size_t len);
  size_t ProcessRstStreamFramePayload(const char* data, size_t len);
  size_t ProcessSettingsFrameHeader(const char* data, size_t len);
  size_t ProcessSettingsFramePayload(const char* data, size_t len);
  size_t ProcessAltSvcFramePayload(const char* data, size_t len);
  size_t ProcessIgnoredControlFramePayload(/*const char* data,*/ size_t len);

  // Validates the frame header against the current protocol, e.g.
  // Frame type must be known, must specify a non-zero stream id.
  //
  // is_control_frame    : the control bit for SPDY3
  // frame_type_field    : the unparsed frame type octet(s)
  // payload_length_field: the stated length in octets of the frame payload
  //
  // For valid frames, returns the correct SpdyFrameType.
  // Otherwise returns a best guess at invalid frame type,
  // after setting the appropriate SpdyError.
  SpdyFrameType ValidateFrameHeader(bool is_control_frame,
                                    int frame_type_field,
                                    size_t payload_length_field);

  // TODO(jgraettinger): To be removed with migration to
  // SpdyHeadersHandlerInterface.  Serializes the last-processed
  // header block of |hpack_decoder_| as a SPDY3 format block, and
  // delivers it to the visitor via reentrant call to
  // ProcessControlFrameHeaderBlock().  |compressed_len| is used for
  // logging compression percentage.
  void DeliverHpackBlockAsSpdy3Block(size_t compressed_len);

  // Helpers for above internal breakouts from ProcessInput.
  void ProcessControlFrameHeader(int control_frame_type_field);
  // Always passed exactly 1 setting's worth of data.
  bool ProcessSetting(const char* data);

  // Retrieve serialized length of SpdyHeaderBlock. If compression is enabled, a
  // maximum estimate is returned.
  size_t GetSerializedLength(const SpdyHeaderBlock& headers);

  // Get (and lazily initialize) the ZLib state.
  z_stream* GetHeaderCompressor();
  z_stream* GetHeaderDecompressor();

  // Get (and lazily initialize) the HPACK state.
  HpackEncoder* GetHpackEncoder();
  HpackDecoderInterface* GetHpackDecoder();

  size_t GetNumberRequiredContinuationFrames(size_t size);

  void WritePayloadWithContinuation(SpdyFrameBuilder* builder,
                                    const std::string& hpack_encoding,
                                    SpdyStreamId stream_id,
                                    SpdyFrameType type,
                                    int padding_payload_len);

  // Deliver the given control frame's uncompressed headers block to the
  // visitor in chunks. Returns true if the visitor has accepted all of the
  // chunks.
  bool IncrementallyDeliverControlFrameHeaderData(SpdyStreamId stream_id,
                                                  const char* data,
                                                  size_t len);

  // Utility to copy the given data block to the current frame buffer, up
  // to the given maximum number of bytes, and update the buffer
  // data (pointer and length). Returns the number of bytes
  // read, and:
  //   *data is advanced the number of bytes read.
  //   *len is reduced by the number of bytes read.
  size_t UpdateCurrentFrameBuffer(const char** data, size_t* len,
                                  size_t max_bytes);

  void WriteHeaderBlockToZ(const SpdyHeaderBlock* headers,
                           z_stream* out) const;

  // Compresses automatically according to enable_compression_.
  void SerializeHeaderBlock(SpdyFrameBuilder* builder,
                            const SpdyFrameWithHeaderBlockIR& frame);

  // Set the error code and moves the framer into the error state.
  void set_error(SpdyError error);

  // The size of the control frame buffer.
  // Since this is only used for control frame headers, the maximum control
  // frame header size (SYN_STREAM) is sufficient; all remaining control
  // frame data is streamed to the visitor.
  static const size_t kControlFrameBufferSize;

  // The maximum size of the control frames that we send, including the size of
  // the header. This limit is arbitrary. We can enforce it here or at the
  // application layer. We chose the framing layer, but this can be changed (or
  // removed) if necessary later down the line.
  // TODO(diannahu): Rename to make it clear that this limit is for sending.
  static const size_t kMaxControlFrameSize;

  SpdyState state_;
  SpdyState previous_state_;
  SpdyError error_code_;

  // Note that for DATA frame, remaining_data_length_ is sum of lengths of
  // frame header, padding length field (optional), data payload (optional) and
  // padding payload (optional).
  size_t remaining_data_length_;

  // The length (in bytes) of the padding payload to be processed.
  size_t remaining_padding_payload_length_;

  // The number of bytes remaining to read from the current control frame's
  // headers. Note that header data blocks (for control types that have them)
  // are part of the frame's payload, and not the frame's headers.
  size_t remaining_control_header_;

  // The limit on HTTP/2 payload size as specified in the
  // SETTINGS_MAX_FRAME_SIZE advertised to peer
  size_t recv_frame_size_limit_ = kSpdyInitialFrameSizeLimit;

  CharBuffer current_frame_buffer_;

  // The type of the frame currently being read.
  SpdyFrameType current_frame_type_;

  // The total length of the frame currently being read, including frame header.
  uint32_t current_frame_length_;

  // The stream ID field of the frame currently being read, if applicable.
  SpdyStreamId current_frame_stream_id_;

  // Set this to the current stream when we receive a HEADERS, PUSH_PROMISE, or
  // CONTINUATION frame without the END_HEADERS(0x4) bit set. These frames must
  // be followed by a CONTINUATION frame, or else we throw a PROTOCOL_ERROR.
  // A value of 0 indicates that we are not expecting a CONTINUATION frame.
  SpdyStreamId expect_continuation_;

  // Scratch space for handling SETTINGS frames.
  // TODO(hkhalil): Unify memory for this scratch space with
  // current_frame_buffer_.
  SpdySettingsScratch settings_scratch_;

  std::unique_ptr<CharBuffer> altsvc_scratch_;

  // SPDY header compressors.
  std::unique_ptr<z_stream> header_compressor_;
  std::unique_ptr<z_stream> header_decompressor_;

  std::unique_ptr<HpackEncoder> hpack_encoder_;
  std::unique_ptr<HpackDecoderInterface> hpack_decoder_;

  SpdyFramerVisitorInterface* visitor_;
  SpdyFramerDebugVisitorInterface* debug_visitor_;

  std::unique_ptr<SpdyHeadersBlockParser> header_parser_;
  SpdyHeadersHandlerInterface* header_handler_;

  std::string display_protocol_;

  // Optional decoder to use instead of this instance.
  std::unique_ptr<SpdyFramerDecoderAdapter> decoder_adapter_;

  // The protocol version to be spoken/understood by this framer.
  const SpdyMajorVersion protocol_version_;

  // The flags field of the frame currently being read.
  uint8_t current_frame_flags_;

  // Determines whether HPACK or gzip compression is used.
  bool enable_compression_;

  // Tracks if we've ever gotten far enough in framing to see a control frame of
  // type SYN_STREAM or SYN_REPLY.
  //
  // If we ever get something which looks like a data frame before we've had a
  // SYN, we explicitly check to see if it looks like we got an HTTP response
  // to a SPDY request.  This boolean lets us do that.
  bool syn_frame_processed_;

  // If we ever get a data frame before a SYN frame, we check to see if it
  // starts with HTTP.  If it does, we likely have an HTTP response.   This
  // isn't guaranteed though: we could have gotten a settings frame and then
  // corrupt data that just looks like HTTP, but deterministic checking requires
  // a lot more state.
  bool probable_http_response_;

  // If a HEADERS frame is followed by a CONTINUATION frame, the FIN/END_STREAM
  // flag is still carried in the HEADERS frame. If it's set, flip this so that
  // we know to terminate the stream when the entire header block has been
  // processed.
  bool end_stream_when_done_;

  // If true, then ProcessInput returns after processing a full frame,
  // rather than reading all available input.
  bool process_single_input_frame_ = false;

  bool enforce_max_frame_size_ =
      FLAGS_chromium_http2_flag_enforce_max_frame_size;
};

}  // namespace net

#endif  // NET_SPDY_SPDY_FRAMER_H_
