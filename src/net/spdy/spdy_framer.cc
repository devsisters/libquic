// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_framer.h"

#include <algorithm>
#include <limits>
#include <string>

#include "base/lazy_instance.h"
#include "base/memory/scoped_ptr.h"
#if 0
#include "base/third_party/valgrind/memcheck.h"
#endif
#include "net/spdy/spdy_frame_builder.h"
#include "net/spdy/spdy_frame_reader.h"
#include "net/spdy/spdy_bitmasks.h"
#include "third_party/zlib/zlib.h"

using base::StringPiece;
using std::string;
using std::vector;

namespace net {

namespace {

// Compute the id of our dictionary so that we know we're using the
// right one when asked for it.
uLong CalculateDictionaryId(const char* dictionary,
                            const size_t dictionary_size) {
  uLong initial_value = adler32(0L, Z_NULL, 0);
  return adler32(initial_value,
                 reinterpret_cast<const Bytef*>(dictionary),
                 dictionary_size);
}

// Check to see if the name and value of a cookie are both empty.
bool IsCookieEmpty(const base::StringPiece& cookie) {
  if (cookie.size() == 0) {
     return true;
  }
  size_t pos = cookie.find('=');
  if (pos  == base::StringPiece::npos) {
     return false;
  }
  // Ignore leading whitespaces of cookie value.
  size_t value_start = pos + 1;
  for (; value_start < cookie.size(); value_start++) {
     if (!(cookie[value_start] == ' ' || cookie[value_start] == '\t')) {
        break;
     }
  }
  return (pos == 0) && ((cookie.size() - value_start) == 0);
}

// Pack parent stream ID and exclusive flag into the format used by HTTP/2
// headers and priority frames.
uint32 PackStreamDependencyValues(bool exclusive,
                                  SpdyStreamId parent_stream_id) {
  // Make sure the highest-order bit in the parent stream id is zeroed out.
  uint32 parent = parent_stream_id & 0x7fffffff;
  // Set the one-bit exclusivity flag.
  uint32 e_bit = exclusive ? 0x80000000 : 0;
  return parent | e_bit;
}

struct DictionaryIds {
  DictionaryIds()
    : v2_dictionary_id(CalculateDictionaryId(kV2Dictionary, kV2DictionarySize)),
      v3_dictionary_id(CalculateDictionaryId(kV3Dictionary, kV3DictionarySize))
  {}
  const uLong v2_dictionary_id;
  const uLong v3_dictionary_id;
};

// Adler ID for the SPDY header compressor dictionaries. Note that they are
// initialized lazily to avoid static initializers.
base::LazyInstance<DictionaryIds>::Leaky g_dictionary_ids;

// Used to indicate no flags in a SPDY flags field.
const uint8 kNoFlags = 0;

// Wire sizes of priority payloads.
const size_t kPriorityDependencyPayloadSize = 4;
const size_t kPriorityWeightPayloadSize = 1;

// Wire size of pad length field.
const size_t kPadLengthFieldSize = 1;

}  // namespace

const SpdyStreamId SpdyFramer::kInvalidStream = static_cast<SpdyStreamId>(-1);
const size_t SpdyFramer::kHeaderDataChunkMaxSize = 1024;
// We fragment sent control frames at smaller payload boundaries.
const size_t SpdyFramer::kMaxControlFrameSize = 1024;
// The size of the control frame buffer. Must be >= the minimum size of the
// largest control frame, which is SYN_STREAM. See GetSynStreamMinimumSize() for
// calculation details.
const size_t SpdyFramer::kControlFrameBufferSize = 19;

#ifdef DEBUG_SPDY_STATE_CHANGES
#define CHANGE_STATE(newstate)                                  \
  do {                                                          \
    DVLOG(1) << "Changing state from: "                         \
             << StateToString(state_)                           \
             << " to " << StateToString(newstate) << "\n";      \
    DCHECK(state_ != SPDY_ERROR);                               \
    DCHECK_EQ(previous_state_, state_);                         \
    previous_state_ = state_;                                   \
    state_ = newstate;                                          \
  } while (false)
#else
#define CHANGE_STATE(newstate)                                  \
  do {                                                          \
    DCHECK(state_ != SPDY_ERROR);                               \
    DCHECK_EQ(previous_state_, state_);                         \
    previous_state_ = state_;                                   \
    state_ = newstate;                                          \
  } while (false)
#endif

SettingsFlagsAndId SettingsFlagsAndId::FromWireFormat(
    SpdyMajorVersion version, uint32 wire) {
  if (version < SPDY3) {
    ConvertFlagsAndIdForSpdy2(&wire);
  }
  return SettingsFlagsAndId(ntohl(wire) >> 24, ntohl(wire) & 0x00ffffff);
}

SettingsFlagsAndId::SettingsFlagsAndId(uint8 flags, uint32 id)
    : flags_(flags), id_(id & 0x00ffffff) {
  LOG_IF(DFATAL, id > (1u << 24)) << "SPDY setting ID too large: " << id;
}

uint32 SettingsFlagsAndId::GetWireFormat(SpdyMajorVersion version)
    const {
  uint32 wire = htonl(id_ & 0x00ffffff) | htonl(flags_ << 24);
  if (version < SPDY3) {
    ConvertFlagsAndIdForSpdy2(&wire);
  }
  return wire;
}

// SPDY 2 had a bug in it with respect to byte ordering of id/flags field.
// This method is used to preserve buggy behavior and works on both
// little-endian and big-endian hosts.
// This method is also bidirectional (can be used to translate SPDY 2 to SPDY 3
// as well as vice versa).
void SettingsFlagsAndId::ConvertFlagsAndIdForSpdy2(uint32* val) {
    uint8* wire_array = reinterpret_cast<uint8*>(val);
    std::swap(wire_array[0], wire_array[3]);
    std::swap(wire_array[1], wire_array[2]);
}

SpdyAltSvcScratch::SpdyAltSvcScratch() { Reset(); }
SpdyAltSvcScratch::~SpdyAltSvcScratch() {}

bool SpdyFramerVisitorInterface::OnGoAwayFrameData(const char* goaway_data,
                                                   size_t len) {
  return true;
}

bool SpdyFramerVisitorInterface::OnRstStreamFrameData(
    const char* rst_stream_data,
    size_t len) {
  return true;
}

SpdyFramer::SpdyFramer(SpdyMajorVersion version)
    : current_frame_buffer_(new char[kControlFrameBufferSize]),
      expect_continuation_(0),
      visitor_(NULL),
      debug_visitor_(NULL),
      display_protocol_("SPDY"),
      protocol_version_(version),
      enable_compression_(true),
      syn_frame_processed_(false),
      probable_http_response_(false),
      end_stream_when_done_(false),
      header_table_size_bound_(4096) {
  DCHECK_GE(protocol_version_, SPDY_MIN_VERSION);
  DCHECK_LE(protocol_version_, SPDY_MAX_VERSION);
  DCHECK_LE(kMaxControlFrameSize,
            SpdyConstants::GetFrameMaximumSize(protocol_version_) +
                SpdyConstants::GetControlFrameHeaderSize(protocol_version_));
  Reset();
}

SpdyFramer::~SpdyFramer() {
  if (header_compressor_.get()) {
    deflateEnd(header_compressor_.get());
  }
  if (header_decompressor_.get()) {
    inflateEnd(header_decompressor_.get());
  }
}

void SpdyFramer::Reset() {
  state_ = SPDY_RESET;
  previous_state_ = SPDY_RESET;
  error_code_ = SPDY_NO_ERROR;
  remaining_data_length_ = 0;
  remaining_control_header_ = 0;
  current_frame_buffer_length_ = 0;
  current_frame_type_ = DATA;
  current_frame_flags_ = 0;
  current_frame_length_ = 0;
  current_frame_stream_id_ = kInvalidStream;
  settings_scratch_.Reset();
  altsvc_scratch_.Reset();
  remaining_padding_payload_length_ = 0;
}

size_t SpdyFramer::GetDataFrameMinimumSize() const {
  return SpdyConstants::GetDataFrameMinimumSize(protocol_version());
}

// Size, in bytes, of the control frame header.
size_t SpdyFramer::GetControlFrameHeaderSize() const {
  return SpdyConstants::GetControlFrameHeaderSize(protocol_version());
}

size_t SpdyFramer::GetSynStreamMinimumSize() const {
  // Size, in bytes, of a SYN_STREAM frame not including the variable-length
  // name-value block.
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 2 * 4 (stream IDs) + 1 (priority)
    // + 1 (unused, was credential slot)
    return GetControlFrameHeaderSize() + 10;
  } else {
    return GetControlFrameHeaderSize() +
        kPriorityDependencyPayloadSize +
        kPriorityWeightPayloadSize;
  }
}

size_t SpdyFramer::GetSynReplyMinimumSize() const {
  // Size, in bytes, of a SYN_REPLY frame not including the variable-length
  // name-value block.
  size_t size = GetControlFrameHeaderSize();
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 4 (stream IDs)
    size += 4;
  }

  // In SPDY 2, there were 2 unused bytes before payload.
  if (protocol_version() < SPDY3) {
    size += 2;
  }

  return size;
}

size_t SpdyFramer::GetRstStreamMinimumSize() const {
  // Size, in bytes, of a RST_STREAM frame.
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 4 (stream id) + 4 (status code)
    return GetControlFrameHeaderSize() + 8;
  } else {
    // Calculated as:
    // frame prefix + 4 (status code)
    return GetControlFrameHeaderSize() + 4;
  }
}

size_t SpdyFramer::GetSettingsMinimumSize() const {
  // Size, in bytes, of a SETTINGS frame not including the IDs and values
  // from the variable-length value block. Calculated as:
  // control frame header + 4 (number of ID/value pairs)
  if (protocol_version() <= SPDY3) {
    return GetControlFrameHeaderSize() + 4;
  } else {
    return GetControlFrameHeaderSize();
  }
}

size_t SpdyFramer::GetPingSize() const {
  // Size, in bytes, of this PING frame.
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 4 (id)
    return GetControlFrameHeaderSize() + 4;
  } else {
    // Calculated as:
    // control frame header + 8 (id)
    return GetControlFrameHeaderSize() + 8;
  }
}

size_t SpdyFramer::GetGoAwayMinimumSize() const {
  // Size, in bytes, of this GOAWAY frame. Calculated as:
  // 1. Control frame header size
  size_t size = GetControlFrameHeaderSize();

  // 2. Last good stream id (4 bytes)
  size += 4;

  // 3. SPDY 3+ GOAWAY frames also contain a status (4 bytes)
  if (protocol_version() >= SPDY3) {
    size += 4;
  }

  return size;
}

size_t SpdyFramer::GetHeadersMinimumSize() const  {
  // Size, in bytes, of a HEADERS frame not including the variable-length
  // name-value block.
  size_t size = GetControlFrameHeaderSize();
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 4 (stream IDs)
    size += 4;
  }

  // In SPDY 2, there were 2 unused bytes before payload.
  if (protocol_version() <= SPDY2) {
    size += 2;
  }

  return size;
}

size_t SpdyFramer::GetWindowUpdateSize() const {
  // Size, in bytes, of a WINDOW_UPDATE frame.
  if (protocol_version() <= SPDY3) {
    // Calculated as:
    // control frame header + 4 (stream id) + 4 (delta)
    return GetControlFrameHeaderSize() + 8;
  } else {
    // Calculated as:
    // frame prefix + 4 (delta)
    return GetControlFrameHeaderSize() + 4;
  }
}

size_t SpdyFramer::GetBlockedSize() const {
  DCHECK_LT(SPDY3, protocol_version());
  // Size, in bytes, of a BLOCKED frame.
  // The BLOCKED frame has no payload beyond the control frame header.
  return GetControlFrameHeaderSize();
}

size_t SpdyFramer::GetPushPromiseMinimumSize() const {
  DCHECK_LT(SPDY3, protocol_version());
  // Size, in bytes, of a PUSH_PROMISE frame, sans the embedded header block.
  // Calculated as frame prefix + 4 (promised stream id).
  return GetControlFrameHeaderSize() + 4;
}

size_t SpdyFramer::GetContinuationMinimumSize() const {
  // Size, in bytes, of a CONTINUATION frame not including the variable-length
  // headers fragments.
  return GetControlFrameHeaderSize();
}

size_t SpdyFramer::GetAltSvcMinimumSize() const {
  // Size, in bytes, of an ALTSVC frame not including the Field-Value and
  // (optional) Origin fields, both of which can vary in length.  Note that this
  // gives a lower bound on the frame size rather than a true minimum; the
  // actual frame should always be larger than this.
  // Calculated as frame prefix + 2 (origin_len).
  return GetControlFrameHeaderSize() + 2;
}

size_t SpdyFramer::GetPrioritySize() const {
  // Size, in bytes, of a PRIORITY frame.
  return GetControlFrameHeaderSize() +
      kPriorityDependencyPayloadSize +
      kPriorityWeightPayloadSize;
}

size_t SpdyFramer::GetFrameMinimumSize() const {
  return std::min(GetDataFrameMinimumSize(), GetControlFrameHeaderSize());
}

size_t SpdyFramer::GetFrameMaximumSize() const {
  return SpdyConstants::GetFrameMaximumSize(protocol_version());
}

size_t SpdyFramer::GetDataFrameMaximumPayload() const {
  return GetFrameMaximumSize() - GetDataFrameMinimumSize();
}

size_t SpdyFramer::GetPrefixLength(SpdyFrameType type) const {
  return SpdyConstants::GetPrefixLength(type, protocol_version());
}

const char* SpdyFramer::StateToString(int state) {
  switch (state) {
    case SPDY_ERROR:
      return "ERROR";
    case SPDY_AUTO_RESET:
      return "AUTO_RESET";
    case SPDY_RESET:
      return "RESET";
    case SPDY_READING_COMMON_HEADER:
      return "READING_COMMON_HEADER";
    case SPDY_CONTROL_FRAME_PAYLOAD:
      return "CONTROL_FRAME_PAYLOAD";
    case SPDY_READ_DATA_FRAME_PADDING_LENGTH:
      return "SPDY_READ_DATA_FRAME_PADDING_LENGTH";
    case SPDY_CONSUME_PADDING:
      return "SPDY_CONSUME_PADDING";
    case SPDY_IGNORE_REMAINING_PAYLOAD:
      return "IGNORE_REMAINING_PAYLOAD";
    case SPDY_FORWARD_STREAM_FRAME:
      return "FORWARD_STREAM_FRAME";
    case SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK:
      return "SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK";
    case SPDY_CONTROL_FRAME_HEADER_BLOCK:
      return "SPDY_CONTROL_FRAME_HEADER_BLOCK";
    case SPDY_GOAWAY_FRAME_PAYLOAD:
      return "SPDY_GOAWAY_FRAME_PAYLOAD";
    case SPDY_RST_STREAM_FRAME_PAYLOAD:
      return "SPDY_RST_STREAM_FRAME_PAYLOAD";
    case SPDY_SETTINGS_FRAME_PAYLOAD:
      return "SPDY_SETTINGS_FRAME_PAYLOAD";
    case SPDY_ALTSVC_FRAME_PAYLOAD:
      return "SPDY_ALTSVC_FRAME_PAYLOAD";
  }
  return "UNKNOWN_STATE";
}

void SpdyFramer::set_error(SpdyError error) {
  DCHECK(visitor_);
  error_code_ = error;
  // These values will usually get reset once we come to the end
  // of a header block, but if we run into an error that
  // might not happen, so reset them here.
  expect_continuation_ = 0;
  end_stream_when_done_ = false;

  CHANGE_STATE(SPDY_ERROR);
  visitor_->OnError(this);
}

const char* SpdyFramer::ErrorCodeToString(int error_code) {
  switch (error_code) {
    case SPDY_NO_ERROR:
      return "NO_ERROR";
    case SPDY_INVALID_CONTROL_FRAME:
      return "INVALID_CONTROL_FRAME";
    case SPDY_CONTROL_PAYLOAD_TOO_LARGE:
      return "CONTROL_PAYLOAD_TOO_LARGE";
    case SPDY_ZLIB_INIT_FAILURE:
      return "ZLIB_INIT_FAILURE";
    case SPDY_UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case SPDY_DECOMPRESS_FAILURE:
      return "DECOMPRESS_FAILURE";
    case SPDY_COMPRESS_FAILURE:
      return "COMPRESS_FAILURE";
    case SPDY_INVALID_DATA_FRAME_FLAGS:
      return "SPDY_INVALID_DATA_FRAME_FLAGS";
    case SPDY_INVALID_CONTROL_FRAME_FLAGS:
      return "SPDY_INVALID_CONTROL_FRAME_FLAGS";
    case SPDY_UNEXPECTED_FRAME:
      return "UNEXPECTED_FRAME";
  }
  return "UNKNOWN_ERROR";
}

const char* SpdyFramer::StatusCodeToString(int status_code) {
  switch (status_code) {
    case RST_STREAM_INVALID:
      return "INVALID";
    case RST_STREAM_PROTOCOL_ERROR:
      return "PROTOCOL_ERROR";
    case RST_STREAM_INVALID_STREAM:
      return "INVALID_STREAM";
    case RST_STREAM_REFUSED_STREAM:
      return "REFUSED_STREAM";
    case RST_STREAM_UNSUPPORTED_VERSION:
      return "UNSUPPORTED_VERSION";
    case RST_STREAM_CANCEL:
      return "CANCEL";
    case RST_STREAM_INTERNAL_ERROR:
      return "INTERNAL_ERROR";
    case RST_STREAM_FLOW_CONTROL_ERROR:
      return "FLOW_CONTROL_ERROR";
    case RST_STREAM_STREAM_IN_USE:
      return "STREAM_IN_USE";
    case RST_STREAM_STREAM_ALREADY_CLOSED:
      return "STREAM_ALREADY_CLOSED";
    case RST_STREAM_INVALID_CREDENTIALS:
      return "INVALID_CREDENTIALS";
    case RST_STREAM_FRAME_TOO_LARGE:
      return "FRAME_TOO_LARGE";
    case RST_STREAM_CONNECT_ERROR:
      return "CONNECT_ERROR";
    case RST_STREAM_ENHANCE_YOUR_CALM:
      return "ENHANCE_YOUR_CALM";
    case RST_STREAM_INADEQUATE_SECURITY:
      return "INADEQUATE_SECURITY";
    case RST_STREAM_HTTP_1_1_REQUIRED:
      return "HTTP_1_1_REQUIRED";
  }
  return "UNKNOWN_STATUS";
}

const char* SpdyFramer::FrameTypeToString(SpdyFrameType type) {
  switch (type) {
    case DATA:
      return "DATA";
    case SYN_STREAM:
      return "SYN_STREAM";
    case SYN_REPLY:
      return "SYN_REPLY";
    case RST_STREAM:
      return "RST_STREAM";
    case SETTINGS:
      return "SETTINGS";
    case PING:
      return "PING";
    case GOAWAY:
      return "GOAWAY";
    case HEADERS:
      return "HEADERS";
    case WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case CREDENTIAL:
      return "CREDENTIAL";
    case PUSH_PROMISE:
      return "PUSH_PROMISE";
    case CONTINUATION:
      return "CONTINUATION";
    case PRIORITY:
      return "PRIORITY";
    case ALTSVC:
      return "ALTSVC";
    case BLOCKED:
      return "BLOCKED";
  }
  return "UNKNOWN_CONTROL_TYPE";
}

size_t SpdyFramer::ProcessInput(const char* data, size_t len) {
  DCHECK(visitor_);
  DCHECK(data);

  size_t original_len = len;
  do {
    previous_state_ = state_;
    switch (state_) {
      case SPDY_ERROR:
        goto bottom;

      case SPDY_AUTO_RESET:
      case SPDY_RESET:
        Reset();
        if (len > 0) {
          CHANGE_STATE(SPDY_READING_COMMON_HEADER);
        }
        break;

      case SPDY_READING_COMMON_HEADER: {
        size_t bytes_read = ProcessCommonHeader(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK: {
        // Control frames that contain header blocks
        // (SYN_STREAM, SYN_REPLY, HEADERS, PUSH_PROMISE, CONTINUATION)
        // take a different path through the state machine - they
        // will go:
        //   1. SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK
        //   2. SPDY_CONTROL_FRAME_HEADER_BLOCK
        //
        // SETTINGS frames take a slightly modified route:
        //   1. SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK
        //   2. SPDY_SETTINGS_FRAME_PAYLOAD
        //
        //  All other control frames will use the alternate route directly to
        //  SPDY_CONTROL_FRAME_PAYLOAD
        int bytes_read = ProcessControlFrameBeforeHeaderBlock(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_SETTINGS_FRAME_PAYLOAD: {
        int bytes_read = ProcessSettingsFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_HEADER_BLOCK: {
        int bytes_read = ProcessControlFrameHeaderBlock(
            data, len, protocol_version() > SPDY3);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_RST_STREAM_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessRstStreamFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_GOAWAY_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessGoAwayFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_ALTSVC_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessAltSvcFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONTROL_FRAME_PAYLOAD: {
        size_t bytes_read = ProcessControlFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_READ_DATA_FRAME_PADDING_LENGTH: {
        size_t bytes_read = ProcessDataFramePaddingLength(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_CONSUME_PADDING: {
        size_t bytes_read = ProcessFramePadding(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_IGNORE_REMAINING_PAYLOAD: {
        size_t bytes_read = ProcessIgnoredControlFramePayload(/*data,*/ len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      case SPDY_FORWARD_STREAM_FRAME: {
        size_t bytes_read = ProcessDataFramePayload(data, len);
        len -= bytes_read;
        data += bytes_read;
        break;
      }

      default:
        LOG(DFATAL) << "Invalid value for " << display_protocol_
                    << " framer state: " << state_;
        // This ensures that we don't infinite-loop if state_ gets an
        // invalid value somehow, such as due to a SpdyFramer getting deleted
        // from a callback it calls.
        goto bottom;
    }
  } while (state_ != previous_state_);
 bottom:
  DCHECK(len == 0 || state_ == SPDY_ERROR);
  if (current_frame_buffer_length_ == 0 &&
      remaining_data_length_ == 0 &&
      remaining_control_header_ == 0) {
    DCHECK(state_ == SPDY_RESET || state_ == SPDY_ERROR)
        << "State: " << StateToString(state_);
  }

  return original_len - len;
}

size_t SpdyFramer::ProcessCommonHeader(const char* data, size_t len) {
  // This should only be called when we're in the SPDY_READING_COMMON_HEADER
  // state.
  DCHECK_EQ(state_, SPDY_READING_COMMON_HEADER);

  size_t original_len = len;

  // Update current frame buffer as needed.
  if (current_frame_buffer_length_ < GetControlFrameHeaderSize()) {
    size_t bytes_desired =
        GetControlFrameHeaderSize() - current_frame_buffer_length_;
    UpdateCurrentFrameBuffer(&data, &len, bytes_desired);
  }

  if (current_frame_buffer_length_ < GetControlFrameHeaderSize()) {
    // Not enough information to do anything meaningful.
    return original_len - len;
  }

  // Using a scoped_ptr here since we may need to create a new SpdyFrameReader
  // when processing DATA frames below.
  scoped_ptr<SpdyFrameReader> reader(
      new SpdyFrameReader(current_frame_buffer_.get(),
                          current_frame_buffer_length_));

  bool is_control_frame = false;

  int control_frame_type_field =
      SpdyConstants::DataFrameType(protocol_version());
  // ProcessControlFrameHeader() will set current_frame_type_ to the
  // correct value if this is a valid control frame.
  current_frame_type_ = DATA;
  if (protocol_version() <= SPDY3) {
    uint16 version = 0;
    bool successful_read = reader->ReadUInt16(&version);
    DCHECK(successful_read);
    is_control_frame = (version & kControlFlagMask) != 0;
    version &= ~kControlFlagMask;  // Only valid for control frames.
    if (is_control_frame) {
      // We check version before we check validity: version can never be
      // 'invalid', it can only be unsupported.
      if (version < SpdyConstants::SerializeMajorVersion(SPDY_MIN_VERSION) ||
          version > SpdyConstants::SerializeMajorVersion(SPDY_MAX_VERSION) ||
          SpdyConstants::ParseMajorVersion(version) != protocol_version()) {
        // Version does not match the version the framer was initialized with.
        DVLOG(1) << "Unsupported SPDY version "
                 << version
                 << " (expected " << protocol_version() << ")";
        set_error(SPDY_UNSUPPORTED_VERSION);
        return 0;
      }
      // We check control_frame_type_field's validity in
      // ProcessControlFrameHeader().
      uint16 control_frame_type_field_uint16;
      successful_read = reader->ReadUInt16(&control_frame_type_field_uint16);
      control_frame_type_field = control_frame_type_field_uint16;
    } else {
      reader->Rewind();
      successful_read = reader->ReadUInt31(&current_frame_stream_id_);
    }
    DCHECK(successful_read);

    successful_read = reader->ReadUInt8(&current_frame_flags_);
    DCHECK(successful_read);

    uint32 length_field = 0;
    successful_read = reader->ReadUInt24(&length_field);
    DCHECK(successful_read);
    remaining_data_length_ = length_field;
    current_frame_length_ = remaining_data_length_ + reader->GetBytesConsumed();
  } else {
    uint32 length_field = 0;
    bool successful_read = reader->ReadUInt24(&length_field);
    DCHECK(successful_read);

    uint8 control_frame_type_field_uint8;
    successful_read = reader->ReadUInt8(&control_frame_type_field_uint8);
    DCHECK(successful_read);
    // We check control_frame_type_field's validity in
    // ProcessControlFrameHeader().
    control_frame_type_field = control_frame_type_field_uint8;
    is_control_frame = control_frame_type_field !=
        SpdyConstants::SerializeFrameType(protocol_version(), DATA);

    if (is_control_frame) {
      current_frame_length_ = length_field + GetControlFrameHeaderSize();
    } else {
      current_frame_length_ = length_field + GetDataFrameMinimumSize();
    }

    successful_read = reader->ReadUInt8(&current_frame_flags_);
    DCHECK(successful_read);

    successful_read = reader->ReadUInt31(&current_frame_stream_id_);
    DCHECK(successful_read);

    remaining_data_length_ = current_frame_length_ - reader->GetBytesConsumed();

    // Before we accept a DATA frame, we need to make sure we're not in the
    // middle of processing a header block.
    const bool is_continuation_frame = (control_frame_type_field ==
        SpdyConstants::SerializeFrameType(protocol_version(), CONTINUATION));
    if ((expect_continuation_ != 0) != is_continuation_frame) {
      if (expect_continuation_ != 0) {
        DLOG(ERROR) << "The framer was expecting to receive a CONTINUATION "
                    << "frame, but instead received frame type "
                    << control_frame_type_field;
      } else {
        DLOG(ERROR) << "The framer received an unexpected CONTINUATION frame.";
      }
      set_error(SPDY_UNEXPECTED_FRAME);
      return original_len - len;
    }
  }
  DCHECK_EQ(is_control_frame ? GetControlFrameHeaderSize()
                             : GetDataFrameMinimumSize(),
            reader->GetBytesConsumed());
  DCHECK_EQ(current_frame_length_,
            remaining_data_length_ + reader->GetBytesConsumed());

  // This is just a sanity check for help debugging early frame errors.
  if (remaining_data_length_ > 1000000u) {
    // The strncmp for 5 is safe because we only hit this point if we
    // have kMinCommonHeader (8) bytes
    if (!syn_frame_processed_ &&
        strncmp(current_frame_buffer_.get(), "HTTP/", 5) == 0) {
      LOG(WARNING) << "Unexpected HTTP response to " << display_protocol_
                   << " request";
      probable_http_response_ = true;
    } else {
      LOG(WARNING) << "Unexpectedly large frame.  " << display_protocol_
                   << " session is likely corrupt.";
    }
  }

  // if we're here, then we have the common header all received.
  if (!is_control_frame) {
    if (protocol_version() > SPDY3) {
      // Catch bogus tests sending oversized DATA frames.
      DCHECK_GE(GetFrameMaximumSize(), current_frame_length_)
          << "DATA frame too large for SPDY >= 4.";
    }

    uint8 valid_data_flags = 0;
    if (protocol_version() > SPDY3) {
      valid_data_flags =
          DATA_FLAG_FIN | DATA_FLAG_END_SEGMENT | DATA_FLAG_PADDED;
    } else {
      valid_data_flags = DATA_FLAG_FIN;
    }

    if (current_frame_flags_ & ~valid_data_flags) {
      set_error(SPDY_INVALID_DATA_FRAME_FLAGS);
    } else {
      visitor_->OnDataFrameHeader(current_frame_stream_id_,
                                  remaining_data_length_,
                                  current_frame_flags_ & DATA_FLAG_FIN);
      if (remaining_data_length_ > 0) {
        CHANGE_STATE(SPDY_READ_DATA_FRAME_PADDING_LENGTH);
      } else {
        // Empty data frame.
        if (current_frame_flags_ & DATA_FLAG_FIN) {
          visitor_->OnStreamFrameData(
              current_frame_stream_id_, NULL, 0, true);
        }
        CHANGE_STATE(SPDY_AUTO_RESET);
      }
    }
  } else {
    ProcessControlFrameHeader(control_frame_type_field);
  }

  return original_len - len;
}

void SpdyFramer::ProcessControlFrameHeader(int control_frame_type_field) {
  DCHECK_EQ(SPDY_NO_ERROR, error_code_);
  DCHECK_LE(GetControlFrameHeaderSize(), current_frame_buffer_length_);

  // TODO(mlavan): Either remove credential frames from the code entirely,
  // or add them to parsing + serialization methods for SPDY3.
  // Early detection of deprecated frames that we ignore.
  if (protocol_version() <= SPDY3) {
    if (control_frame_type_field == CREDENTIAL) {
      current_frame_type_ = CREDENTIAL;
      DCHECK_EQ(SPDY3, protocol_version());
      DVLOG(1) << "CREDENTIAL control frame found. Ignoring.";
      CHANGE_STATE(SPDY_IGNORE_REMAINING_PAYLOAD);
      return;
    }
  }

  if (!SpdyConstants::IsValidFrameType(protocol_version(),
                                       control_frame_type_field)) {
    if (protocol_version() <= SPDY3) {
      DLOG(WARNING) << "Invalid control frame type " << control_frame_type_field
                    << " (protocol version: " << protocol_version() << ")";
      set_error(SPDY_INVALID_CONTROL_FRAME);
      return;
    } else {
      // In HTTP2 we ignore unknown frame types for extensibility, as long as
      // the rest of the control frame header is valid.
      // We rely on the visitor to check validity of current_frame_stream_id_.
      bool valid_stream = visitor_->OnUnknownFrame(current_frame_stream_id_,
                                                   control_frame_type_field);
      if (valid_stream) {
        DVLOG(1) << "Ignoring unknown frame type.";
        CHANGE_STATE(SPDY_IGNORE_REMAINING_PAYLOAD);
      } else {
        // Report an invalid frame error and close the stream if the
        // stream_id is not valid.
        DLOG(WARNING) << "Unknown control frame type "
                      << control_frame_type_field
                      << " received on invalid stream "
                      << current_frame_stream_id_;
        set_error(SPDY_INVALID_CONTROL_FRAME);
      }
      return;
    }
  }

  current_frame_type_ = SpdyConstants::ParseFrameType(protocol_version(),
                                                      control_frame_type_field);

  // Do some sanity checking on the control frame sizes and flags.
  switch (current_frame_type_) {
    case SYN_STREAM:
      if (current_frame_length_ < GetSynStreamMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ &
                 ~(CONTROL_FLAG_FIN | CONTROL_FLAG_UNIDIRECTIONAL)) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case SYN_REPLY:
      if (current_frame_length_ < GetSynReplyMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ & ~CONTROL_FLAG_FIN) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case RST_STREAM:
      // For SPDY versions < 4, the header has a fixed length.
      // For SPDY version 4 and up, the RST_STREAM frame may include optional
      // opaque data, so we only have a lower limit on the frame size.
      if ((current_frame_length_ != GetRstStreamMinimumSize() &&
           protocol_version() <= SPDY3) ||
          (current_frame_length_ < GetRstStreamMinimumSize() &&
           protocol_version() > SPDY3)) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case SETTINGS:
    {
      // Make sure that we have an integral number of 8-byte key/value pairs,
      // plus a 4-byte length field in SPDY3 and below.
      size_t values_prefix_size = (protocol_version() <= SPDY3 ? 4 : 0);
      // Size of each key/value pair in bytes.
      size_t setting_size = SpdyConstants::GetSettingSize(protocol_version());
      if (current_frame_length_ < GetSettingsMinimumSize() ||
          (current_frame_length_ - GetControlFrameHeaderSize())
          % setting_size != values_prefix_size) {
        DLOG(WARNING) << "Invalid length for SETTINGS frame: "
                      << current_frame_length_;
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (protocol_version() <= SPDY3 &&
                 current_frame_flags_ &
                 ~SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      } else if (protocol_version() > SPDY3 &&
                 current_frame_flags_ & ~SETTINGS_FLAG_ACK) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      } else if (protocol_version() > SPDY3 &&
                 current_frame_flags_ & SETTINGS_FLAG_ACK &&
                 current_frame_length_ > GetSettingsMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      }
      break;
    }
    case PING:
      if (current_frame_length_ != GetPingSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if ((protocol_version() <= SPDY3 && current_frame_flags_ != 0) ||
                 (current_frame_flags_ & ~PING_FLAG_ACK)) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case GOAWAY:
      {
        // For SPDY version < 4, there are only mandatory fields and the header
        // has a fixed length. For SPDY version >= 4, optional opaque data may
        // be appended to the GOAWAY frame, thus there is only a minimal length
        // restriction.
        if ((current_frame_length_ != GetGoAwayMinimumSize() &&
             protocol_version() <= SPDY3) ||
            (current_frame_length_ < GetGoAwayMinimumSize() &&
             protocol_version() > SPDY3)) {
          set_error(SPDY_INVALID_CONTROL_FRAME);
        } else if (current_frame_flags_ != 0) {
          set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
        }
        break;
      }
    case HEADERS:
      {
        size_t min_size = GetHeadersMinimumSize();
        if (protocol_version() > SPDY3 &&
            (current_frame_flags_ & HEADERS_FLAG_PRIORITY)) {
          min_size += 4;
        }
        if (current_frame_length_ < min_size) {
          // TODO(mlavan): check here for HEADERS with no payload?
          // (not allowed in HTTP2)
          set_error(SPDY_INVALID_CONTROL_FRAME);
        } else if (protocol_version() <= SPDY3 &&
                   current_frame_flags_ & ~CONTROL_FLAG_FIN) {
          set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
        } else if (protocol_version() > SPDY3 &&
                   current_frame_flags_ &
                       ~(CONTROL_FLAG_FIN | HEADERS_FLAG_PRIORITY |
                         HEADERS_FLAG_END_HEADERS | HEADERS_FLAG_END_SEGMENT |
                         HEADERS_FLAG_PADDED)) {
          set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
        }
      }
      break;
    case WINDOW_UPDATE:
      if (current_frame_length_ != GetWindowUpdateSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case BLOCKED:
      if (current_frame_length_ != GetBlockedSize() ||
          protocol_version() <= SPDY3) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case PUSH_PROMISE:
      if (current_frame_length_ < GetPushPromiseMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (protocol_version() <= SPDY3 && current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      } else if (protocol_version() > SPDY3 &&
                 current_frame_flags_ &
                     ~(PUSH_PROMISE_FLAG_END_PUSH_PROMISE |
                       HEADERS_FLAG_PADDED)) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case CONTINUATION:
      if (current_frame_length_ < GetContinuationMinimumSize() ||
          protocol_version() <= SPDY3) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ & ~HEADERS_FLAG_END_HEADERS) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case ALTSVC:
      if (current_frame_length_ <= GetAltSvcMinimumSize()) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    case PRIORITY:
      if (current_frame_length_ != GetPrioritySize() ||
          protocol_version() <= SPDY3) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
      } else if (current_frame_flags_ != 0) {
        set_error(SPDY_INVALID_CONTROL_FRAME_FLAGS);
      }
      break;
    default:
      LOG(WARNING) << "Valid " << display_protocol_
                   << " control frame with unhandled type: "
                   << current_frame_type_;
      // This branch should be unreachable because of the frame type bounds
      // check above. However, we DLOG(FATAL) here in an effort to painfully
      // club the head of the developer who failed to keep this file in sync
      // with spdy_protocol.h.
      DLOG(FATAL);
      set_error(SPDY_INVALID_CONTROL_FRAME);
      break;
  }

  if (state_ == SPDY_ERROR) {
    return;
  }

  if (current_frame_length_ >
      SpdyConstants::GetFrameMaximumSize(protocol_version()) +
          SpdyConstants::GetControlFrameHeaderSize(protocol_version())) {
    DLOG(WARNING) << "Received control frame of type " << current_frame_type_
                  << " with way too big of a payload: "
                  << current_frame_length_;
    set_error(SPDY_CONTROL_PAYLOAD_TOO_LARGE);
    return;
  }

  if (current_frame_type_ == GOAWAY) {
    CHANGE_STATE(SPDY_GOAWAY_FRAME_PAYLOAD);
    return;
  }

  if (current_frame_type_ == RST_STREAM) {
    CHANGE_STATE(SPDY_RST_STREAM_FRAME_PAYLOAD);
    return;
  }

  if (current_frame_type_ == ALTSVC) {
    CHANGE_STATE(SPDY_ALTSVC_FRAME_PAYLOAD);
    return;
  }
  // Determine the frame size without variable-length data.
  int32 frame_size_without_variable_data;
  switch (current_frame_type_) {
    case SYN_STREAM:
      syn_frame_processed_ = true;
      frame_size_without_variable_data = GetSynStreamMinimumSize();
      break;
    case SYN_REPLY:
      syn_frame_processed_ = true;
      frame_size_without_variable_data = GetSynReplyMinimumSize();
      break;
    case SETTINGS:
      frame_size_without_variable_data = GetSettingsMinimumSize();
      break;
    case HEADERS:
      frame_size_without_variable_data = GetHeadersMinimumSize();
      if (protocol_version() > SPDY3) {
        if (current_frame_flags_ & HEADERS_FLAG_PADDED) {
          frame_size_without_variable_data += kPadLengthFieldSize;
        }
        if (current_frame_flags_ & HEADERS_FLAG_PRIORITY) {
        frame_size_without_variable_data +=
            kPriorityDependencyPayloadSize +
            kPriorityWeightPayloadSize;
        }
      }
      break;
    case PUSH_PROMISE:
      frame_size_without_variable_data = GetPushPromiseMinimumSize();
      if (protocol_version() > SPDY3 &&
          current_frame_flags_ & PUSH_PROMISE_FLAG_PADDED) {
        frame_size_without_variable_data += kPadLengthFieldSize;
      }
      break;
    case CONTINUATION:
      frame_size_without_variable_data = GetContinuationMinimumSize();
      break;
    default:
      frame_size_without_variable_data = -1;
      break;
  }

  if ((frame_size_without_variable_data == -1) &&
      (current_frame_length_ > kControlFrameBufferSize)) {
    // We should already be in an error state. Double-check.
    DCHECK_EQ(SPDY_ERROR, state_);
    if (state_ != SPDY_ERROR) {
      LOG(DFATAL) << display_protocol_
                  << " control frame buffer too small for fixed-length frame.";
      set_error(SPDY_CONTROL_PAYLOAD_TOO_LARGE);
    }
    return;
  }

  if (frame_size_without_variable_data > 0) {
    // We have a control frame with a header block. We need to parse the
    // remainder of the control frame's header before we can parse the header
    // block. The start of the header block varies with the control type.
    DCHECK_GE(frame_size_without_variable_data,
              static_cast<int32>(current_frame_buffer_length_));
    remaining_control_header_ = frame_size_without_variable_data -
        current_frame_buffer_length_;

    CHANGE_STATE(SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK);
    return;
  }

  CHANGE_STATE(SPDY_CONTROL_FRAME_PAYLOAD);
}

size_t SpdyFramer::UpdateCurrentFrameBuffer(const char** data, size_t* len,
                                            size_t max_bytes) {
  size_t bytes_to_read = std::min(*len, max_bytes);
  if (bytes_to_read > 0) {
    DCHECK_GE(kControlFrameBufferSize,
              current_frame_buffer_length_ + bytes_to_read);
    memcpy(current_frame_buffer_.get() + current_frame_buffer_length_,
           *data,
           bytes_to_read);
    current_frame_buffer_length_ += bytes_to_read;
    *data += bytes_to_read;
    *len -= bytes_to_read;
  }
  return bytes_to_read;
}

size_t SpdyFramer::GetSerializedLength(
    const SpdyMajorVersion spdy_version,
    const SpdyHeaderBlock* headers) {
  const size_t num_name_value_pairs_size
      = (spdy_version < SPDY3) ? sizeof(uint16) : sizeof(uint32);
  const size_t length_of_name_size = num_name_value_pairs_size;
  const size_t length_of_value_size = num_name_value_pairs_size;

  size_t total_length = num_name_value_pairs_size;
  for (SpdyHeaderBlock::const_iterator it = headers->begin();
       it != headers->end();
       ++it) {
    // We add space for the length of the name and the length of the value as
    // well as the length of the name and the length of the value.
    total_length += length_of_name_size + it->first.size() +
                    length_of_value_size + it->second.size();
  }
  return total_length;
}

void SpdyFramer::WriteHeaderBlock(SpdyFrameBuilder* frame,
                                  const SpdyMajorVersion spdy_version,
                                  const SpdyHeaderBlock* headers) {
  if (spdy_version < SPDY3) {
    frame->WriteUInt16(static_cast<uint16>(headers->size()));
  } else {
    frame->WriteUInt32(headers->size());
  }
  SpdyHeaderBlock::const_iterator it;
  for (it = headers->begin(); it != headers->end(); ++it) {
    if (spdy_version < SPDY3) {
      frame->WriteStringPiece16(it->first);
      frame->WriteStringPiece16(it->second);
    } else {
      frame->WriteStringPiece32(it->first);
      frame->WriteStringPiece32(it->second);
    }
  }
}

// TODO(phajdan.jr): Clean up after we no longer need
// to workaround http://crbug.com/139744.
#if !defined(USE_SYSTEM_ZLIB)

// These constants are used by zlib to differentiate between normal data and
// cookie data. Cookie data is handled specially by zlib when compressing.
enum ZDataClass {
  // kZStandardData is compressed normally, save that it will never match
  // against any other class of data in the window.
  kZStandardData = Z_CLASS_STANDARD,
  // kZCookieData is compressed in its own Huffman blocks and only matches in
  // its entirety and only against other kZCookieData blocks. Any matches must
  // be preceeded by a kZStandardData byte, or a semicolon to prevent matching
  // a suffix. It's assumed that kZCookieData ends in a semicolon to prevent
  // prefix matches.
  kZCookieData = Z_CLASS_COOKIE,
  // kZHuffmanOnlyData is only Huffman compressed - no matches are performed
  // against the window.
  kZHuffmanOnlyData = Z_CLASS_HUFFMAN_ONLY,
};

// WriteZ writes |data| to the deflate context |out|. WriteZ will flush as
// needed when switching between classes of data.
static void WriteZ(const base::StringPiece& data,
                   ZDataClass clas,
                   z_stream* out) {
  int rv;

  // If we are switching from standard to non-standard data then we need to end
  // the current Huffman context to avoid it leaking between them.
  if (out->clas == kZStandardData &&
      clas != kZStandardData) {
    out->avail_in = 0;
    rv = deflate(out, Z_PARTIAL_FLUSH);
    DCHECK_EQ(Z_OK, rv);
    DCHECK_EQ(0u, out->avail_in);
    DCHECK_LT(0u, out->avail_out);
  }

  out->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
  out->avail_in = data.size();
  out->clas = clas;
  if (clas == kZStandardData) {
    rv = deflate(out, Z_NO_FLUSH);
  } else {
    rv = deflate(out, Z_PARTIAL_FLUSH);
  }
  if (!data.empty()) {
    // If we didn't provide any data then zlib will return Z_BUF_ERROR.
    DCHECK_EQ(Z_OK, rv);
  }
  DCHECK_EQ(0u, out->avail_in);
  DCHECK_LT(0u, out->avail_out);
}

// WriteLengthZ writes |n| as a |length|-byte, big-endian number to |out|.
static void WriteLengthZ(size_t n,
                         unsigned length,
                         ZDataClass clas,
                         z_stream* out) {
  char buf[4];
  DCHECK_LE(length, sizeof(buf));
  for (unsigned i = 1; i <= length; i++) {
    buf[length - i] = static_cast<char>(n);
    n >>= 8;
  }
  WriteZ(base::StringPiece(buf, length), clas, out);
}

// WriteHeaderBlockToZ serialises |headers| to the deflate context |z| in a
// manner that resists the length of the compressed data from compromising
// cookie data.
void SpdyFramer::WriteHeaderBlockToZ(const SpdyHeaderBlock* headers,
                                     z_stream* z) const {
  unsigned length_length = 4;
  if (protocol_version() < 3)
    length_length = 2;

  WriteLengthZ(headers->size(), length_length, kZStandardData, z);

  std::map<std::string, std::string>::const_iterator it;
  for (it = headers->begin(); it != headers->end(); ++it) {
    WriteLengthZ(it->first.size(), length_length, kZStandardData, z);
    WriteZ(it->first, kZStandardData, z);

    if (it->first == "cookie") {
      // We require the cookie values (save for the last) to end with a
      // semicolon and (save for the first) to start with a space. This is
      // typically the format that we are given them in but we reserialize them
      // to be sure.

      std::vector<base::StringPiece> cookie_values;
      size_t cookie_length = 0;
      base::StringPiece cookie_data(it->second);

      for (;;) {
        while (!cookie_data.empty() &&
               (cookie_data[0] == ' ' || cookie_data[0] == '\t')) {
          cookie_data.remove_prefix(1);
        }
        if (cookie_data.empty())
          break;

        size_t i;
        for (i = 0; i < cookie_data.size(); i++) {
          if (cookie_data[i] == ';')
            break;
        }
        if (i < cookie_data.size()) {
          if (!IsCookieEmpty(cookie_data.substr(0, i))) {
            cookie_values.push_back(cookie_data.substr(0, i));
            cookie_length += i + 2 /* semicolon and space */;
          }
          cookie_data.remove_prefix(i + 1);
        } else {
          if (!IsCookieEmpty(cookie_data)) {
            cookie_values.push_back(cookie_data);
            cookie_length += cookie_data.size();
          } else if (cookie_length > 2) {
            cookie_length -= 2 /* compensate for previously added length */;
          }
          cookie_data.remove_prefix(i);
        }
      }

      WriteLengthZ(cookie_length, length_length, kZStandardData, z);
      for (size_t i = 0; i < cookie_values.size(); i++) {
        std::string cookie;
        // Since zlib will only back-reference complete cookies, a cookie that
        // is currently last (and so doesn't have a trailing semicolon) won't
        // match if it's later in a non-final position. The same is true of
        // the first cookie.
        if (i == 0 && cookie_values.size() == 1) {
          cookie = cookie_values[i].as_string();
        } else if (i == 0) {
          cookie = cookie_values[i].as_string() + ";";
        } else if (i < cookie_values.size() - 1) {
          cookie = " " + cookie_values[i].as_string() + ";";
        } else {
          cookie = " " + cookie_values[i].as_string();
        }
        WriteZ(cookie, kZCookieData, z);
      }
    } else if (it->first == "accept" ||
               it->first == "accept-charset" ||
               it->first == "accept-encoding" ||
               it->first == "accept-language" ||
               it->first == "host" ||
               it->first == "version" ||
               it->first == "method" ||
               it->first == "scheme" ||
               it->first == ":host" ||
               it->first == ":version" ||
               it->first == ":method" ||
               it->first == ":scheme" ||
               it->first == "user-agent") {
      WriteLengthZ(it->second.size(), length_length, kZStandardData, z);
      WriteZ(it->second, kZStandardData, z);
    } else {
      // Non-whitelisted headers are Huffman compressed in their own block, but
      // don't match against the window.
      WriteLengthZ(it->second.size(), length_length, kZStandardData, z);
      WriteZ(it->second, kZHuffmanOnlyData, z);
    }
  }

  z->avail_in = 0;
  int rv = deflate(z, Z_SYNC_FLUSH);
  DCHECK_EQ(Z_OK, rv);
  z->clas = kZStandardData;
}

#endif  // !defined(USE_SYSTEM_ZLIB)

size_t SpdyFramer::ProcessControlFrameBeforeHeaderBlock(const char* data,
                                                        size_t len) {
  DCHECK_EQ(SPDY_CONTROL_FRAME_BEFORE_HEADER_BLOCK, state_);
  const size_t original_len = len;

  if (remaining_control_header_ > 0) {
    size_t bytes_read = UpdateCurrentFrameBuffer(&data, &len,
                                                 remaining_control_header_);
    remaining_control_header_ -= bytes_read;
    remaining_data_length_ -= bytes_read;
  }

  if (remaining_control_header_ == 0) {
    SpdyFrameReader reader(current_frame_buffer_.get(),
                           current_frame_buffer_length_);
    reader.Seek(GetControlFrameHeaderSize());  // Seek past frame header.

    switch (current_frame_type_) {
      case SYN_STREAM:
        {
          DCHECK_GE(SPDY3, protocol_version());
          bool successful_read = true;
          successful_read = reader.ReadUInt31(&current_frame_stream_id_);
          DCHECK(successful_read);
          if (current_frame_stream_id_ == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            break;
          }

          SpdyStreamId associated_to_stream_id = kInvalidStream;
          successful_read = reader.ReadUInt31(&associated_to_stream_id);
          DCHECK(successful_read);

          SpdyPriority priority = 0;
          successful_read = reader.ReadUInt8(&priority);
          DCHECK(successful_read);
          if (protocol_version() <= SPDY2) {
            priority = priority >> 6;
          } else {
            priority = priority >> 5;
          }

          // Seek past unused byte; used to be credential slot in SPDY 3.
          reader.Seek(1);

          DCHECK(reader.IsDoneReading());
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          visitor_->OnSynStream(
              current_frame_stream_id_,
              associated_to_stream_id,
              priority,
              (current_frame_flags_ & CONTROL_FLAG_FIN) != 0,
              (current_frame_flags_ & CONTROL_FLAG_UNIDIRECTIONAL) != 0);
        }
        CHANGE_STATE(SPDY_CONTROL_FRAME_HEADER_BLOCK);
        break;
      case SETTINGS:
        if (protocol_version() > SPDY3 &&
            current_frame_flags_ & SETTINGS_FLAG_ACK) {
          visitor_->OnSettingsAck();
          CHANGE_STATE(SPDY_AUTO_RESET);
        } else {
          visitor_->OnSettings(current_frame_flags_ &
              SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS);
          CHANGE_STATE(SPDY_SETTINGS_FRAME_PAYLOAD);
        }
        break;
      case SYN_REPLY:
      case HEADERS:
        // SYN_REPLY and HEADERS are the same, save for the visitor call.
        {
          if (protocol_version() > SPDY3) {
            DCHECK_EQ(HEADERS, current_frame_type_);
          }
          bool successful_read = true;
          if (protocol_version() <= SPDY3) {
            successful_read = reader.ReadUInt31(&current_frame_stream_id_);
            DCHECK(successful_read);
          }
          if (current_frame_stream_id_ == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            break;
          }
          if (protocol_version() <= SPDY2) {
            // SPDY 2 had two unused bytes here. Seek past them.
            reader.Seek(2);
          }
          if (protocol_version() > SPDY3 &&
             !(current_frame_flags_ & HEADERS_FLAG_END_HEADERS) &&
             current_frame_type_ == HEADERS) {
            expect_continuation_ = current_frame_stream_id_;
            end_stream_when_done_ = current_frame_flags_ & CONTROL_FLAG_FIN;
          }
          if (protocol_version() > SPDY3 &&
              current_frame_flags_ & HEADERS_FLAG_PADDED) {
            uint8 pad_payload_len = 0;
            DCHECK_EQ(remaining_padding_payload_length_, 0u);
            successful_read = reader.ReadUInt8(&pad_payload_len);
            DCHECK(successful_read);
            remaining_padding_payload_length_ = pad_payload_len;
          }
          const bool has_priority =
              (current_frame_flags_ & HEADERS_FLAG_PRIORITY) != 0;
          SpdyPriority priority = 0;
          if (protocol_version() > SPDY3 && has_priority) {
            // TODO(jgraettinger): Process dependency rather than ignoring it.
            reader.Seek(kPriorityDependencyPayloadSize);
            uint8 weight = 0;
            successful_read = reader.ReadUInt8(&weight);
            if (successful_read) {
              priority = MapWeightToPriority(weight);
            }
          }
          DCHECK(reader.IsDoneReading());
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          if (current_frame_type_ == SYN_REPLY) {
            visitor_->OnSynReply(
                current_frame_stream_id_,
                (current_frame_flags_ & CONTROL_FLAG_FIN) != 0);
          } else {
            visitor_->OnHeaders(
                current_frame_stream_id_,
                (current_frame_flags_ & HEADERS_FLAG_PRIORITY) != 0, priority,
                (current_frame_flags_ & CONTROL_FLAG_FIN) != 0,
                expect_continuation_ == 0);
          }
        }
        CHANGE_STATE(SPDY_CONTROL_FRAME_HEADER_BLOCK);
        break;
      case PUSH_PROMISE:
        {
          DCHECK_LT(SPDY3, protocol_version());
          if (current_frame_stream_id_ == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            break;
          }
          bool successful_read = true;
          if (protocol_version() > SPDY3 &&
              current_frame_flags_ & PUSH_PROMISE_FLAG_PADDED) {
            DCHECK_EQ(remaining_padding_payload_length_, 0u);
            uint8 pad_payload_len = 0;
            successful_read = reader.ReadUInt8(&pad_payload_len);
            DCHECK(successful_read);
            remaining_padding_payload_length_ = pad_payload_len;
          }
        }
        {
          SpdyStreamId promised_stream_id = kInvalidStream;
          bool successful_read = reader.ReadUInt31(&promised_stream_id);
          DCHECK(successful_read);
          DCHECK(reader.IsDoneReading());
          if (promised_stream_id == 0) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            break;
          }
          if (!(current_frame_flags_ & PUSH_PROMISE_FLAG_END_PUSH_PROMISE)) {
            expect_continuation_ = current_frame_stream_id_;
          }
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          visitor_->OnPushPromise(current_frame_stream_id_,
                                  promised_stream_id,
                                  (current_frame_flags_ &
                                   PUSH_PROMISE_FLAG_END_PUSH_PROMISE) != 0);
        }
        CHANGE_STATE(SPDY_CONTROL_FRAME_HEADER_BLOCK);
        break;
      case CONTINUATION:
        {
          // Check to make sure the stream id of the current frame is
          // the same as that of the preceding frame.
          // If we're at this point we should already know that
          // expect_continuation_ != 0, so this doubles as a check
          // that current_frame_stream_id != 0.
          if (current_frame_stream_id_ != expect_continuation_) {
            set_error(SPDY_INVALID_CONTROL_FRAME);
            break;
          }
          if (current_frame_flags_ & HEADERS_FLAG_END_HEADERS) {
            expect_continuation_ = 0;
          }
          if (debug_visitor_) {
            debug_visitor_->OnReceiveCompressedFrame(
                current_frame_stream_id_,
                current_frame_type_,
                current_frame_length_);
          }
          visitor_->OnContinuation(current_frame_stream_id_,
                                   (current_frame_flags_ &
                                    HEADERS_FLAG_END_HEADERS) != 0);
        }
        CHANGE_STATE(SPDY_CONTROL_FRAME_HEADER_BLOCK);
        break;
      default:
        DCHECK(false);
    }
  }
  return original_len - len;
}

// Does not buffer the control payload. Instead, either passes directly to the
// visitor or decompresses and then passes directly to the visitor, via
// IncrementallyDeliverControlFrameHeaderData() or
// IncrementallyDecompressControlFrameHeaderData() respectively.
size_t SpdyFramer::ProcessControlFrameHeaderBlock(const char* data,
                                                  size_t data_len,
                                                  bool is_hpack_header_block) {
  DCHECK_EQ(SPDY_CONTROL_FRAME_HEADER_BLOCK, state_);

  bool processed_successfully = true;
  if (current_frame_type_ != SYN_STREAM &&
      current_frame_type_ != SYN_REPLY &&
      current_frame_type_ != HEADERS &&
      current_frame_type_ != PUSH_PROMISE &&
      current_frame_type_ != CONTINUATION) {
    LOG(DFATAL) << "Unhandled frame type in ProcessControlFrameHeaderBlock.";
  }
  size_t process_bytes = std::min(
      data_len, remaining_data_length_ - remaining_padding_payload_length_);
  if (is_hpack_header_block) {
    if (!GetHpackDecoder()->HandleControlFrameHeadersData(
            current_frame_stream_id_, data, process_bytes)) {
      // TODO(jgraettinger): Finer-grained HPACK error codes.
      set_error(SPDY_DECOMPRESS_FAILURE);
      processed_successfully = false;
    }
  } else if (process_bytes > 0) {
    if (enable_compression_ && protocol_version() <= SPDY3) {
      processed_successfully = IncrementallyDecompressControlFrameHeaderData(
          current_frame_stream_id_, data, process_bytes);
    } else {
      processed_successfully = IncrementallyDeliverControlFrameHeaderData(
          current_frame_stream_id_, data, process_bytes);
    }
  }
  remaining_data_length_ -= process_bytes;

  // Handle the case that there is no futher data in this frame.
  if (remaining_data_length_ == remaining_padding_payload_length_ &&
      processed_successfully) {
    if (expect_continuation_ == 0) {
      if (is_hpack_header_block) {
        if (!GetHpackDecoder()->HandleControlFrameHeadersComplete(
                current_frame_stream_id_)) {
          set_error(SPDY_DECOMPRESS_FAILURE);
          processed_successfully = false;
        } else {
          // TODO(jgraettinger): To be removed with migration to
          // SpdyHeadersHandlerInterface. Serializes the HPACK block as a SPDY3
          // block, delivered via reentrant call to
          // ProcessControlFrameHeaderBlock().
          DeliverHpackBlockAsSpdy3Block();
          return process_bytes;
        }
      } else {
        // The complete header block has been delivered. We send a zero-length
        // OnControlFrameHeaderData() to indicate this.
        visitor_->OnControlFrameHeaderData(current_frame_stream_id_, NULL, 0);
      }
    }
    if (processed_successfully) {
      CHANGE_STATE(SPDY_CONSUME_PADDING);
    }
  }

  // Handle error.
  if (!processed_successfully) {
    return data_len;
  }

  // Return amount processed.
  return process_bytes;
}

size_t SpdyFramer::ProcessSettingsFramePayload(const char* data,
                                               size_t data_len) {
  DCHECK_EQ(SPDY_SETTINGS_FRAME_PAYLOAD, state_);
  DCHECK_EQ(SETTINGS, current_frame_type_);
  size_t unprocessed_bytes = std::min(data_len, remaining_data_length_);
  size_t processed_bytes = 0;

  size_t setting_size = SpdyConstants::GetSettingSize(protocol_version());

  // Loop over our incoming data.
  while (unprocessed_bytes > 0) {
    // Process up to one setting at a time.
    size_t processing = std::min(
        unprocessed_bytes,
        static_cast<size_t>(setting_size - settings_scratch_.setting_buf_len));

    // Check if we have a complete setting in our input.
    if (processing == setting_size) {
      // Parse the setting directly out of the input without buffering.
      if (!ProcessSetting(data + processed_bytes)) {
        set_error(SPDY_INVALID_CONTROL_FRAME);
        return processed_bytes;
      }
    } else {
      // Continue updating settings_scratch_.setting_buf.
      memcpy(settings_scratch_.setting_buf + settings_scratch_.setting_buf_len,
             data + processed_bytes,
             processing);
      settings_scratch_.setting_buf_len += processing;

      // Check if we have a complete setting buffered.
      if (settings_scratch_.setting_buf_len == setting_size) {
        if (!ProcessSetting(settings_scratch_.setting_buf)) {
          set_error(SPDY_INVALID_CONTROL_FRAME);
          return processed_bytes;
        }
        // Reset settings_scratch_.setting_buf for our next setting.
        settings_scratch_.setting_buf_len = 0;
      }
    }

    // Iterate.
    unprocessed_bytes -= processing;
    processed_bytes += processing;
  }

  // Check if we're done handling this SETTINGS frame.
  remaining_data_length_ -= processed_bytes;
  if (remaining_data_length_ == 0) {
    visitor_->OnSettingsEnd();
    CHANGE_STATE(SPDY_AUTO_RESET);
  }

  return processed_bytes;
}

void SpdyFramer::DeliverHpackBlockAsSpdy3Block() {
  DCHECK_LT(SPDY3, protocol_version());
  DCHECK_EQ(remaining_padding_payload_length_, remaining_data_length_);

  const SpdyNameValueBlock& block = GetHpackDecoder()->decoded_block();
  if (block.empty()) {
    // Special-case this to make tests happy.
    ProcessControlFrameHeaderBlock(NULL, 0, false);
    return;
  }
  SpdyFrameBuilder builder(
      GetSerializedLength(protocol_version(), &block),
      SPDY3);

  SerializeNameValueBlockWithoutCompression(&builder, block);
  scoped_ptr<SpdyFrame> frame(builder.take());

  // Preserve padding length, and reset it after the re-entrant call.
  size_t remaining_padding = remaining_padding_payload_length_;

  remaining_padding_payload_length_ = 0;
  remaining_data_length_ = frame->size();

  ProcessControlFrameHeaderBlock(frame->data(), frame->size(), false);

  remaining_padding_payload_length_ = remaining_padding;
  remaining_data_length_ = remaining_padding;
}

bool SpdyFramer::ProcessSetting(const char* data) {
  int id_field;
  SpdySettingsIds id;
  uint8 flags = 0;
  uint32 value;

  // Extract fields.
  // Maintain behavior of old SPDY 2 bug with byte ordering of flags/id.
  if (protocol_version() <= SPDY3) {
    const uint32 id_and_flags_wire = *(reinterpret_cast<const uint32*>(data));
    SettingsFlagsAndId id_and_flags =
      SettingsFlagsAndId::FromWireFormat(protocol_version(), id_and_flags_wire);
    id_field = id_and_flags.id();
    flags = id_and_flags.flags();
    value = ntohl(*(reinterpret_cast<const uint32*>(data + 4)));
  } else {
    id_field = ntohs(*(reinterpret_cast<const uint16*>(data)));
    value = ntohl(*(reinterpret_cast<const uint32*>(data + 2)));
  }

  // Validate id.
  if (!SpdyConstants::IsValidSettingId(protocol_version(), id_field)) {
    DLOG(WARNING) << "Unknown SETTINGS ID: " << id_field;
    if (protocol_version() <= SPDY3) {
      return false;
    } else {
      // In HTTP2 we ignore unknown settings for extensibility.
      return true;
    }
  }
  id = SpdyConstants::ParseSettingId(protocol_version(), id_field);

  if (protocol_version() <= SPDY3) {
    // Detect duplicates.
    if (id <= settings_scratch_.last_setting_id) {
      DLOG(WARNING) << "Duplicate entry or invalid ordering for id " << id
                    << " in " << display_protocol_ << " SETTINGS frame "
                    << "(last setting id was "
                    << settings_scratch_.last_setting_id << ").";
      return false;
    }
    settings_scratch_.last_setting_id = id;

    // Validate flags.
    uint8 kFlagsMask = SETTINGS_FLAG_PLEASE_PERSIST | SETTINGS_FLAG_PERSISTED;
    if ((flags & ~(kFlagsMask)) != 0) {
      DLOG(WARNING) << "Unknown SETTINGS flags provided for id " << id << ": "
                    << flags;
      return false;
    }
  }

  // Validation succeeded. Pass on to visitor.
  visitor_->OnSetting(id, flags, value);
  return true;
}

size_t SpdyFramer::ProcessControlFramePayload(const char* data, size_t len) {
  size_t original_len = len;
  size_t bytes_read = UpdateCurrentFrameBuffer(&data, &len,
                                               remaining_data_length_);
  remaining_data_length_ -= bytes_read;
  if (remaining_data_length_ == 0) {
    SpdyFrameReader reader(current_frame_buffer_.get(),
                           current_frame_buffer_length_);
    reader.Seek(GetControlFrameHeaderSize());  // Skip frame header.

    // Use frame-specific handlers.
    switch (current_frame_type_) {
      case PING: {
          SpdyPingId id = 0;
          bool is_ack = protocol_version() > SPDY3 &&
              (current_frame_flags_ & PING_FLAG_ACK);
          bool successful_read = true;
          if (protocol_version() <= SPDY3) {
            uint32 id32 = 0;
            successful_read = reader.ReadUInt32(&id32);
            id = id32;
          } else {
            successful_read = reader.ReadUInt64(&id);
          }
          DCHECK(successful_read);
          DCHECK(reader.IsDoneReading());
          visitor_->OnPing(id, is_ack);
        }
        break;
      case WINDOW_UPDATE: {
          uint32 delta_window_size = 0;
          bool successful_read = true;
          if (protocol_version() <= SPDY3) {
            successful_read = reader.ReadUInt31(&current_frame_stream_id_);
            DCHECK(successful_read);
          }
          successful_read = reader.ReadUInt32(&delta_window_size);
          DCHECK(successful_read);
          DCHECK(reader.IsDoneReading());
          visitor_->OnWindowUpdate(current_frame_stream_id_,
                                   delta_window_size);
        }
        break;
      case BLOCKED: {
          DCHECK_LT(SPDY3, protocol_version());
          DCHECK(reader.IsDoneReading());
          visitor_->OnBlocked(current_frame_stream_id_);
        }
        break;
      case PRIORITY: {
          DCHECK_LT(SPDY3, protocol_version());
          uint32 parent_stream_id;
          uint8 weight;
          bool exclusive;
          bool successful_read = true;
          successful_read = reader.ReadUInt32(&parent_stream_id);
          DCHECK(successful_read);
          // Exclusivity is indicated by a single bit flag.
          exclusive = (parent_stream_id >> 31) != 0;
          // Zero out the highest-order bit to get the parent stream id.
          parent_stream_id &= 0x7fffffff;
          successful_read = reader.ReadUInt8(&weight);
          DCHECK(successful_read);
          DCHECK(reader.IsDoneReading());
          visitor_->OnPriority(
              current_frame_stream_id_, parent_stream_id, weight, exclusive);
        }
        break;
      default:
        // Unreachable.
        LOG(FATAL) << "Unhandled control frame " << current_frame_type_;
    }

    CHANGE_STATE(SPDY_IGNORE_REMAINING_PAYLOAD);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessGoAwayFramePayload(const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  // Clamp to the actual remaining payload.
  if (len > remaining_data_length_) {
    len = remaining_data_length_;
  }
  size_t original_len = len;

  // Check if we had already read enough bytes to parse the GOAWAY header.
  const size_t header_size = GetGoAwayMinimumSize();
  size_t unread_header_bytes = header_size - current_frame_buffer_length_;
  bool already_parsed_header = (unread_header_bytes == 0);
  if (!already_parsed_header) {
    // Buffer the new GOAWAY header bytes we got.
    UpdateCurrentFrameBuffer(&data, &len, unread_header_bytes);

    // Do we have enough to parse the constant size GOAWAY header?
    if (current_frame_buffer_length_ == header_size) {
      // Parse out the last good stream id.
      SpdyFrameReader reader(current_frame_buffer_.get(),
                             current_frame_buffer_length_);
      reader.Seek(GetControlFrameHeaderSize());  // Seek past frame header.
      bool successful_read = reader.ReadUInt31(&current_frame_stream_id_);
      DCHECK(successful_read);

      // In SPDYv3 and up, frames also specify a status code - parse it out.
      SpdyGoAwayStatus status = GOAWAY_OK;
      if (protocol_version() >= SPDY3) {
        uint32 status_raw = GOAWAY_OK;
        successful_read = reader.ReadUInt32(&status_raw);
        DCHECK(successful_read);
        if (SpdyConstants::IsValidGoAwayStatus(protocol_version(),
                                               status_raw)) {
          status = SpdyConstants::ParseGoAwayStatus(protocol_version(),
                                                    status_raw);
        } else {
          if (protocol_version() > SPDY3) {
            // Treat unrecognized status codes as INTERNAL_ERROR as
            // recommended by the HTTP/2 spec.
            status = GOAWAY_INTERNAL_ERROR;
          }
        }
      }
      // Finished parsing the GOAWAY header, call frame handler.
      visitor_->OnGoAway(current_frame_stream_id_, status);
    }
  }

  // Handle remaining data as opaque.
  bool processed_successfully = true;
  if (len > 0) {
    processed_successfully = visitor_->OnGoAwayFrameData(data, len);
  }
  remaining_data_length_ -= original_len;
  if (!processed_successfully) {
    set_error(SPDY_GOAWAY_FRAME_CORRUPT);
  } else if (remaining_data_length_ == 0) {
    // Signal that there is not more opaque data.
    visitor_->OnGoAwayFrameData(NULL, 0);
    CHANGE_STATE(SPDY_AUTO_RESET);
  }
  return original_len;
}

size_t SpdyFramer::ProcessRstStreamFramePayload(const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }
  // Clamp to the actual remaining payload.
  if (len > remaining_data_length_) {
    len = remaining_data_length_;
  }
  size_t original_len = len;

  // Check if we had already read enough bytes to parse the fixed-length portion
  // of the RST_STREAM frame.
  const size_t header_size = GetRstStreamMinimumSize();
  size_t unread_header_bytes = header_size - current_frame_buffer_length_;
  bool already_parsed_header = (unread_header_bytes == 0);
  if (!already_parsed_header) {
    // Buffer the new RST_STREAM header bytes we got.
    UpdateCurrentFrameBuffer(&data, &len, unread_header_bytes);

    // Do we have enough to parse the constant size RST_STREAM header?
    if (current_frame_buffer_length_ == header_size) {
      // Parse out the last good stream id.
      SpdyFrameReader reader(current_frame_buffer_.get(),
                             current_frame_buffer_length_);
      reader.Seek(GetControlFrameHeaderSize());  // Seek past frame header.
      if (protocol_version() <= SPDY3) {
        bool successful_read = reader.ReadUInt31(&current_frame_stream_id_);
        DCHECK(successful_read);
      }

      SpdyRstStreamStatus status = RST_STREAM_INVALID;
      uint32 status_raw = status;
      bool successful_read = reader.ReadUInt32(&status_raw);
      DCHECK(successful_read);
      if (SpdyConstants::IsValidRstStreamStatus(protocol_version(),
                                                status_raw)) {
        status =
            SpdyConstants::ParseRstStreamStatus(protocol_version(), status_raw);
      } else {
        if (protocol_version() > SPDY3) {
          // Treat unrecognized status codes as INTERNAL_ERROR as
          // recommended by the HTTP/2 spec.
          status = RST_STREAM_INTERNAL_ERROR;
        }
      }
      // Finished parsing the RST_STREAM header, call frame handler.
      visitor_->OnRstStream(current_frame_stream_id_, status);
    }
  }

  // Handle remaining data as opaque.
  bool processed_successfully = true;
  if (len > 0) {
    processed_successfully = visitor_->OnRstStreamFrameData(data, len);
  }
  remaining_data_length_ -= original_len;
  if (!processed_successfully) {
    set_error(SPDY_RST_STREAM_FRAME_CORRUPT);
  } else if (remaining_data_length_ == 0) {
    // Signal that there is not more opaque data.
    visitor_->OnRstStreamFrameData(NULL, 0);
    CHANGE_STATE(SPDY_AUTO_RESET);
  }
  return original_len;
}

size_t SpdyFramer::ProcessAltSvcFramePayload(const char* data, size_t len) {
  if (len == 0) {
    return 0;
  }

  // Clamp to the actual remaining payload.
  len = std::min(len, remaining_data_length_);

  if (altsvc_scratch_.buffer.get() == nullptr) {
    altsvc_scratch_.buffer.reset(
        new char[current_frame_length_ - GetControlFrameHeaderSize()]);
    altsvc_scratch_.buffer_length = 0;
  }
  memcpy(altsvc_scratch_.buffer.get() + altsvc_scratch_.buffer_length, data,
         len);
  altsvc_scratch_.buffer_length += len;
  remaining_data_length_ -= len;
  if (remaining_data_length_ > 0) {
    return len;
  }

  SpdyFrameReader reader(altsvc_scratch_.buffer.get(),
                         altsvc_scratch_.buffer_length);
  StringPiece origin;
  bool successful_read = reader.ReadStringPiece16(&origin);
  if (!successful_read) {
    set_error(SPDY_INVALID_CONTROL_FRAME);
    return 0;
  }
  StringPiece value(altsvc_scratch_.buffer.get() + reader.GetBytesConsumed(),
                    altsvc_scratch_.buffer_length - reader.GetBytesConsumed());

  SpdyAltSvcWireFormat::AlternativeServiceVector altsvc_vector;
  bool success =
      SpdyAltSvcWireFormat::ParseHeaderFieldValue(value, &altsvc_vector);
  if (!success) {
    set_error(SPDY_INVALID_CONTROL_FRAME);
    return 0;
  }

  visitor_->OnAltSvc(current_frame_stream_id_, origin, altsvc_vector);
  CHANGE_STATE(SPDY_AUTO_RESET);
  return len;
}

size_t SpdyFramer::ProcessDataFramePaddingLength(const char* data, size_t len) {
  DCHECK_EQ(SPDY_READ_DATA_FRAME_PADDING_LENGTH, state_);
  DCHECK_EQ(0u, remaining_padding_payload_length_);
  DCHECK_EQ(DATA, current_frame_type_);

  size_t original_len = len;
  if (current_frame_flags_ & DATA_FLAG_PADDED) {
    if (len != 0) {
      if (remaining_data_length_ < kPadLengthFieldSize) {
        set_error(SPDY_INVALID_DATA_FRAME_FLAGS);
        return 0;
      }

      static_assert(kPadLengthFieldSize == 1,
                    "Unexpected pad length field size.");
      remaining_padding_payload_length_ = *reinterpret_cast<const uint8*>(data);
      ++data;
      --len;
      --remaining_data_length_;
      visitor_->OnStreamPadding(current_frame_stream_id_, kPadLengthFieldSize);
    } else {
      // We don't have the data available for parsing the pad length field. Keep
      // waiting.
      return 0;
    }
  }

  if (remaining_padding_payload_length_ > remaining_data_length_) {
    set_error(SPDY_INVALID_DATA_FRAME_FLAGS);
    return 0;
  }
  CHANGE_STATE(SPDY_FORWARD_STREAM_FRAME);
  return original_len - len;
}

size_t SpdyFramer::ProcessFramePadding(const char* data, size_t len) {
  DCHECK_EQ(SPDY_CONSUME_PADDING, state_);

  size_t original_len = len;
  if (remaining_padding_payload_length_ > 0) {
    DCHECK_EQ(remaining_padding_payload_length_, remaining_data_length_);
    size_t amount_to_discard = std::min(remaining_padding_payload_length_, len);
    if (current_frame_type_ == DATA && amount_to_discard > 0) {
      DCHECK_LE(HTTP2, protocol_version());
      visitor_->OnStreamPadding(current_frame_stream_id_, amount_to_discard);
    }
    data += amount_to_discard;
    len -= amount_to_discard;
    remaining_padding_payload_length_ -= amount_to_discard;
    remaining_data_length_ -= amount_to_discard;
  }

  if (remaining_data_length_ == 0) {
    // If the FIN flag is set, or this ends a header block which set FIN,
    // inform the visitor of EOF via a 0-length data frame.
    if (expect_continuation_ == 0 &&
        ((current_frame_flags_ & CONTROL_FLAG_FIN) != 0 ||
         end_stream_when_done_)) {
      end_stream_when_done_ = false;
      visitor_->OnStreamFrameData(current_frame_stream_id_, NULL, 0, true);
    }
    CHANGE_STATE(SPDY_AUTO_RESET);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessDataFramePayload(const char* data, size_t len) {
  size_t original_len = len;
  if (remaining_data_length_ - remaining_padding_payload_length_ > 0) {
    size_t amount_to_forward = std::min(
        remaining_data_length_ - remaining_padding_payload_length_, len);
    if (amount_to_forward && state_ != SPDY_IGNORE_REMAINING_PAYLOAD) {
      // Only inform the visitor if there is data.
      if (amount_to_forward) {
        visitor_->OnStreamFrameData(
            current_frame_stream_id_, data, amount_to_forward, false);
      }
    }
    data += amount_to_forward;
    len -= amount_to_forward;
    remaining_data_length_ -= amount_to_forward;
  }

  if (remaining_data_length_ == remaining_padding_payload_length_) {
    CHANGE_STATE(SPDY_CONSUME_PADDING);
  }
  return original_len - len;
}

size_t SpdyFramer::ProcessIgnoredControlFramePayload(/*const char* data,*/
                                                     size_t len) {
  size_t original_len = len;
  if (remaining_data_length_ > 0) {
    size_t amount_to_ignore = std::min(remaining_data_length_, len);
    len -= amount_to_ignore;
    remaining_data_length_ -= amount_to_ignore;
  }

  if (remaining_data_length_ == 0) {
    CHANGE_STATE(SPDY_AUTO_RESET);
  }
  return original_len - len;
}

size_t SpdyFramer::ParseHeaderBlockInBuffer(const char* header_data,
                                          size_t header_length,
                                          SpdyHeaderBlock* block) const {
  SpdyFrameReader reader(header_data, header_length);

  // Read number of headers.
  uint32 num_headers;
  if (protocol_version() <= SPDY2) {
    uint16 temp;
    if (!reader.ReadUInt16(&temp)) {
      DVLOG(1) << "Unable to read number of headers.";
      return 0;
    }
    num_headers = temp;
  } else {
    if (!reader.ReadUInt32(&num_headers)) {
      DVLOG(1) << "Unable to read number of headers.";
      return 0;
    }
  }

  // Read each header.
  for (uint32 index = 0; index < num_headers; ++index) {
    base::StringPiece temp;

    // Read header name.
    if ((protocol_version() <= SPDY2) ? !reader.ReadStringPiece16(&temp)
                            : !reader.ReadStringPiece32(&temp)) {
      DVLOG(1) << "Unable to read header name (" << index + 1 << " of "
               << num_headers << ").";
      return 0;
    }
    std::string name = temp.as_string();

    // Read header value.
    if ((protocol_version() <= SPDY2) ? !reader.ReadStringPiece16(&temp)
                            : !reader.ReadStringPiece32(&temp)) {
      DVLOG(1) << "Unable to read header value (" << index + 1 << " of "
               << num_headers << ").";
      return 0;
    }
    std::string value = temp.as_string();

    // Ensure no duplicates.
    if (block->find(name) != block->end()) {
      DVLOG(1) << "Duplicate header '" << name << "' (" << index + 1 << " of "
               << num_headers << ").";
      return 0;
    }

    // Store header.
    (*block)[name] = value;
  }
  return reader.GetBytesConsumed();
}

SpdySerializedFrame* SpdyFramer::SerializeData(
    const SpdyDataIR& data_ir) const {
  uint8 flags = DATA_FLAG_NONE;
  if (data_ir.fin()) {
    flags = DATA_FLAG_FIN;
  }

  if (protocol_version() > SPDY3) {
    int num_padding_fields = 0;
    if (data_ir.padded()) {
      flags |= DATA_FLAG_PADDED;
      ++num_padding_fields;
    }

    const size_t size_with_padding = num_padding_fields +
        data_ir.data().length() + data_ir.padding_payload_len() +
        GetDataFrameMinimumSize();
    SpdyFrameBuilder builder(size_with_padding, protocol_version());
    builder.WriteDataFrameHeader(*this, data_ir.stream_id(), flags);
    if (data_ir.padded()) {
      builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
    }
    builder.WriteBytes(data_ir.data().data(), data_ir.data().length());
    if (data_ir.padding_payload_len() > 0) {
      string padding(data_ir.padding_payload_len(), 0);
      builder.WriteBytes(padding.data(), padding.length());
    }
    DCHECK_EQ(size_with_padding, builder.length());
    return builder.take();
  } else {
    const size_t size = GetDataFrameMinimumSize() + data_ir.data().length();
    SpdyFrameBuilder builder(size, protocol_version());
    builder.WriteDataFrameHeader(*this, data_ir.stream_id(), flags);
    builder.WriteBytes(data_ir.data().data(), data_ir.data().length());
    DCHECK_EQ(size, builder.length());
    return builder.take();
  }
}

SpdySerializedFrame* SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(
    const SpdyDataIR& data_ir) const {
  uint8 flags = DATA_FLAG_NONE;
  if (data_ir.fin()) {
    flags = DATA_FLAG_FIN;
  }

  size_t frame_size = GetDataFrameMinimumSize();
  size_t num_padding_fields = 0;
  if (protocol_version() > SPDY3) {
    if (data_ir.padded()) {
      flags |= DATA_FLAG_PADDED;
      ++num_padding_fields;
    }
    frame_size += num_padding_fields;
  }

  SpdyFrameBuilder builder(frame_size, protocol_version());
  builder.WriteDataFrameHeader(*this, data_ir.stream_id(), flags);
  if (protocol_version() > SPDY3) {
    if (data_ir.padded()) {
      builder.WriteUInt8(data_ir.padding_payload_len() & 0xff);
    }
    builder.OverwriteLength(*this,  num_padding_fields +
        data_ir.data().length() + data_ir.padding_payload_len());
  } else {
    builder.OverwriteLength(*this, data_ir.data().length());
  }
  DCHECK_EQ(frame_size, builder.length());
  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeSynStream(
    const SpdySynStreamIR& syn_stream) {
  DCHECK_GE(SPDY3, protocol_version());
  uint8 flags = 0;
  if (syn_stream.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }
  if (syn_stream.unidirectional()) {
    // TODO(hkhalil): invalid for HTTP2.
    flags |= CONTROL_FLAG_UNIDIRECTIONAL;
  }

  // Sanitize priority.
  uint8 priority = syn_stream.priority();
  if (priority > GetLowestPriority()) {
    DLOG(DFATAL) << "Priority out-of-bounds.";
    priority = GetLowestPriority();
  }

  // The size of this frame, including variable-length name-value block.
  size_t size = GetSynStreamMinimumSize() +
      GetSerializedLength(syn_stream.name_value_block());

  SpdyFrameBuilder builder(size, protocol_version());
  builder.WriteControlFrameHeader(*this, SYN_STREAM, flags);
  builder.WriteUInt32(syn_stream.stream_id());
  builder.WriteUInt32(syn_stream.associated_to_stream_id());
  builder.WriteUInt8(priority << ((protocol_version() <= SPDY2) ? 6 : 5));
  builder.WriteUInt8(0);  // Unused byte where credential slot used to be.
  DCHECK_EQ(GetSynStreamMinimumSize(), builder.length());
  SerializeNameValueBlock(&builder, syn_stream);

  if (debug_visitor_) {
    const size_t payload_len =
        GetSerializedLength(protocol_version(),
                            &(syn_stream.name_value_block()));
    debug_visitor_->OnSendCompressedFrame(syn_stream.stream_id(),
                                          SYN_STREAM,
                                          payload_len,
                                          builder.length());
  }

  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeSynReply(
    const SpdySynReplyIR& syn_reply) {
  DCHECK_GE(SPDY3, protocol_version());
  uint8 flags = 0;
  if (syn_reply.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }

  // The size of this frame, including variable-length name-value block.
  const size_t size = GetSynReplyMinimumSize() +
                      GetSerializedLength(syn_reply.name_value_block());

  SpdyFrameBuilder builder(size, protocol_version());
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, SYN_REPLY, flags);
    builder.WriteUInt32(syn_reply.stream_id());
  } else {
    builder.BeginNewFrame(*this,
                          HEADERS,
                          flags,
                          syn_reply.stream_id());
  }
  if (protocol_version() < SPDY3) {
    builder.WriteUInt16(0);  // Unused.
  }
  DCHECK_EQ(GetSynReplyMinimumSize(), builder.length());
  SerializeNameValueBlock(&builder, syn_reply);

  if (debug_visitor_) {
    const size_t payload_len = GetSerializedLength(
        protocol_version(), &(syn_reply.name_value_block()));
    debug_visitor_->OnSendCompressedFrame(syn_reply.stream_id(),
                                          SYN_REPLY,
                                          payload_len,
                                          builder.length());
  }

  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeRstStream(
    const SpdyRstStreamIR& rst_stream) const {
  // TODO(jgraettinger): For now, Chromium will support parsing RST_STREAM
  // payloads, but will not emit them. SPDY4 is used for draft HTTP/2,
  // which doesn't currently include RST_STREAM payloads. GFE flags have been
  // commented but left in place to simplify future patching.
  // Compute the output buffer size, taking opaque data into account.
  size_t expected_length = GetRstStreamMinimumSize();
  if (protocol_version() > SPDY3) {
    expected_length += rst_stream.description().size();
  }
  SpdyFrameBuilder builder(expected_length, protocol_version());

  // Serialize the RST_STREAM frame.
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, RST_STREAM, 0);
    builder.WriteUInt32(rst_stream.stream_id());
  } else {
    builder.BeginNewFrame(*this, RST_STREAM, 0, rst_stream.stream_id());
  }

  builder.WriteUInt32(SpdyConstants::SerializeRstStreamStatus(
      protocol_version(), rst_stream.status()));

  // In HTTP2 and up, RST_STREAM frames may also specify opaque data.
  if (protocol_version() > SPDY3 && rst_stream.description().size() > 0) {
    builder.WriteBytes(rst_stream.description().data(),
                       rst_stream.description().size());
  }

  DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeSettings(
    const SpdySettingsIR& settings) const {
  uint8 flags = 0;

  if (protocol_version() <= SPDY3) {
    if (settings.clear_settings()) {
      flags |= SETTINGS_FLAG_CLEAR_PREVIOUSLY_PERSISTED_SETTINGS;
    }
  } else {
    if (settings.is_ack()) {
      flags |= SETTINGS_FLAG_ACK;
    }
  }
  const SpdySettingsIR::ValueMap* values = &(settings.values());

  size_t setting_size = SpdyConstants::GetSettingSize(protocol_version());
  // Size, in bytes, of this SETTINGS frame.
  const size_t size = GetSettingsMinimumSize() +
                      (values->size() * setting_size);
  SpdyFrameBuilder builder(size, protocol_version());
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, SETTINGS, flags);
  } else {
    builder.BeginNewFrame(*this, SETTINGS, flags, 0);
  }

  // If this is an ACK, payload should be empty.
  if (protocol_version() > SPDY3 && settings.is_ack()) {
    return builder.take();
  }

  if (protocol_version() <= SPDY3) {
    builder.WriteUInt32(values->size());
  }
  DCHECK_EQ(GetSettingsMinimumSize(), builder.length());
  for (SpdySettingsIR::ValueMap::const_iterator it = values->begin();
       it != values->end();
       ++it) {
    int setting_id =
        SpdyConstants::SerializeSettingId(protocol_version(), it->first);
    DCHECK_GE(setting_id, 0);
    if (protocol_version() <= SPDY3) {
      uint8 setting_flags = 0;
      if (it->second.persist_value) {
        setting_flags |= SETTINGS_FLAG_PLEASE_PERSIST;
      }
      if (it->second.persisted) {
        setting_flags |= SETTINGS_FLAG_PERSISTED;
      }
      SettingsFlagsAndId flags_and_id(setting_flags, setting_id);
      uint32 id_and_flags_wire = flags_and_id.GetWireFormat(protocol_version());
      builder.WriteBytes(&id_and_flags_wire, 4);
    } else {
      builder.WriteUInt16(static_cast<uint16>(setting_id));
    }
    builder.WriteUInt32(it->second.value);
  }
  DCHECK_EQ(size, builder.length());
  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializePing(const SpdyPingIR& ping) const {
  SpdyFrameBuilder builder(GetPingSize(), protocol_version());
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, PING, kNoFlags);
    builder.WriteUInt32(static_cast<uint32>(ping.id()));
  } else {
    uint8 flags = 0;
    if (ping.is_ack()) {
      flags |= PING_FLAG_ACK;
    }
    builder.BeginNewFrame(*this, PING, flags, 0);
    builder.WriteUInt64(ping.id());
  }
  DCHECK_EQ(GetPingSize(), builder.length());
  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeGoAway(
    const SpdyGoAwayIR& goaway) const {

  // Compute the output buffer size, take opaque data into account.
  size_t expected_length = GetGoAwayMinimumSize();
  if (protocol_version() > SPDY3) {
    expected_length += goaway.description().size();
  }
  SpdyFrameBuilder builder(expected_length, protocol_version());

  // Serialize the GOAWAY frame.
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, GOAWAY, kNoFlags);
  } else {
    builder.BeginNewFrame(*this, GOAWAY, 0, 0);
  }

  // GOAWAY frames specify the last good stream id for all SPDY versions.
  builder.WriteUInt32(goaway.last_good_stream_id());

  // In SPDY3 and up, GOAWAY frames also specify the error status code.
  if (protocol_version() >= SPDY3) {
    // TODO(jgraettinger): Merge back to server-side.
    builder.WriteUInt32(SpdyConstants::SerializeGoAwayStatus(protocol_version(),
                                                             goaway.status()));
  }

  // In HTTP2 and up, GOAWAY frames may also specify opaque data.
  if ((protocol_version() > SPDY3) && (goaway.description().size() > 0)) {
    builder.WriteBytes(goaway.description().data(),
                       goaway.description().size());
  }

  DCHECK_EQ(expected_length, builder.length());
  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeHeaders(
    const SpdyHeadersIR& headers) {
  uint8 flags = 0;
  if (headers.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }
  if (protocol_version() > SPDY3) {
    // This will get overwritten if we overflow into a CONTINUATION frame.
    flags |= HEADERS_FLAG_END_HEADERS;
    if (headers.has_priority()) {
      flags |= HEADERS_FLAG_PRIORITY;
    }
    if (headers.padded()) {
      flags |= HEADERS_FLAG_PADDED;
    }
  }

  // The size of this frame, including padding (if there is any)
  // and variable-length name-value block.
  size_t size = GetHeadersMinimumSize();

  if (protocol_version() > SPDY3 && headers.padded()) {
    size += kPadLengthFieldSize;
    size += headers.padding_payload_len();
  }

  SpdyPriority priority = static_cast<SpdyPriority>(headers.priority());
  if (headers.has_priority()) {
    if (headers.priority() > GetLowestPriority()) {
      DLOG(DFATAL) << "Priority out-of-bounds.";
      priority = GetLowestPriority();
    }
    size += 5;
  }

  string hpack_encoding;
  if (protocol_version() > SPDY3) {
    if (enable_compression_) {
      GetHpackEncoder()->EncodeHeaderSet(
          headers.name_value_block(), &hpack_encoding);
    } else {
      GetHpackEncoder()->EncodeHeaderSetWithoutCompression(
          headers.name_value_block(), &hpack_encoding);
    }
    size += hpack_encoding.size();
    if (size > kMaxControlFrameSize) {
      size += GetNumberRequiredContinuationFrames(size) *
              GetContinuationMinimumSize();
      flags &= ~HEADERS_FLAG_END_HEADERS;
    }
  } else {
    size += GetSerializedLength(headers.name_value_block());
  }

  SpdyFrameBuilder builder(size, protocol_version());
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, HEADERS, flags);
    builder.WriteUInt32(headers.stream_id());
  } else {
    builder.BeginNewFrame(*this,
                          HEADERS,
                          flags,
                          headers.stream_id());
  }
  if (protocol_version() <= SPDY2) {
    builder.WriteUInt16(0);  // Unused.
  }
  DCHECK_EQ(GetHeadersMinimumSize(), builder.length());

  if (protocol_version() > SPDY3) {
    int padding_payload_len = 0;
    if (headers.padded()) {
      builder.WriteUInt8(headers.padding_payload_len());
      padding_payload_len = headers.padding_payload_len();
    }
    if (headers.has_priority()) {
      builder.WriteUInt32(PackStreamDependencyValues(
          headers.exclusive(), headers.parent_stream_id()));
      builder.WriteUInt8(MapPriorityToWeight(priority));
    }
    WritePayloadWithContinuation(&builder,
                                 hpack_encoding,
                                 headers.stream_id(),
                                 HEADERS,
                                 padding_payload_len);
  } else {
    SerializeNameValueBlock(&builder, headers);
  }

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len =
        GetSerializedLength(protocol_version(),
                            &(headers.name_value_block()));
    debug_visitor_->OnSendCompressedFrame(headers.stream_id(),
                                          HEADERS,
                                          payload_len,
                                          builder.length());
  }

  return builder.take();
}

SpdySerializedFrame* SpdyFramer::SerializeWindowUpdate(
    const SpdyWindowUpdateIR& window_update) const {
  SpdyFrameBuilder builder(GetWindowUpdateSize(), protocol_version());
  if (protocol_version() <= SPDY3) {
    builder.WriteControlFrameHeader(*this, WINDOW_UPDATE, kNoFlags);
    builder.WriteUInt32(window_update.stream_id());
  } else {
    builder.BeginNewFrame(*this,
                          WINDOW_UPDATE,
                          kNoFlags,
                          window_update.stream_id());
  }
  builder.WriteUInt32(window_update.delta());
  DCHECK_EQ(GetWindowUpdateSize(), builder.length());
  return builder.take();
}

SpdyFrame* SpdyFramer::SerializeBlocked(const SpdyBlockedIR& blocked) const {
  DCHECK_LT(SPDY3, protocol_version());
  SpdyFrameBuilder builder(GetBlockedSize(), protocol_version());
  builder.BeginNewFrame(*this, BLOCKED, kNoFlags, blocked.stream_id());
  return builder.take();
}

SpdyFrame* SpdyFramer::SerializePushPromise(
    const SpdyPushPromiseIR& push_promise) {
  DCHECK_LT(SPDY3, protocol_version());
  uint8 flags = 0;
  // This will get overwritten if we overflow into a CONTINUATION frame.
  flags |= PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  // The size of this frame, including variable-length name-value block.
  size_t size = GetPushPromiseMinimumSize();

  if (push_promise.padded()) {
    flags |= PUSH_PROMISE_FLAG_PADDED;
    size += kPadLengthFieldSize;
    size += push_promise.padding_payload_len();
  }

  string hpack_encoding;
  if (enable_compression_) {
    GetHpackEncoder()->EncodeHeaderSet(
        push_promise.name_value_block(), &hpack_encoding);
  } else {
    GetHpackEncoder()->EncodeHeaderSetWithoutCompression(
        push_promise.name_value_block(), &hpack_encoding);
  }
  size += hpack_encoding.size();
  if (size > kMaxControlFrameSize) {
    size += GetNumberRequiredContinuationFrames(size) *
            GetContinuationMinimumSize();
    flags &= ~PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }

  SpdyFrameBuilder builder(size, protocol_version());
  builder.BeginNewFrame(*this,
                        PUSH_PROMISE,
                        flags,
                        push_promise.stream_id());
  int padding_payload_len = 0;
  if (push_promise.padded()) {
    builder.WriteUInt8(push_promise.padding_payload_len());
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize() + kPadLengthFieldSize,
              builder.length());

    padding_payload_len = push_promise.padding_payload_len();
  } else {
    builder.WriteUInt32(push_promise.promised_stream_id());
    DCHECK_EQ(GetPushPromiseMinimumSize(), builder.length());
  }

  WritePayloadWithContinuation(&builder,
                               hpack_encoding,
                               push_promise.stream_id(),
                               PUSH_PROMISE,
                               padding_payload_len);

  if (debug_visitor_) {
    // HTTP2 uses HPACK for header compression. However, continue to
    // use GetSerializedLength() for an apples-to-apples comparision of
    // compression performance between HPACK and SPDY w/ deflate.
    const size_t payload_len =
        GetSerializedLength(protocol_version(),
                            &(push_promise.name_value_block()));
    debug_visitor_->OnSendCompressedFrame(push_promise.stream_id(),
                                          PUSH_PROMISE,
                                          payload_len,
                                          builder.length());
  }

  return builder.take();
}

// TODO(jgraettinger): This implementation is incorrect. The continuation
// frame continues a previously-begun HPACK encoding; it doesn't begin a
// new one. Figure out whether it makes sense to keep SerializeContinuation().
SpdyFrame* SpdyFramer::SerializeContinuation(
    const SpdyContinuationIR& continuation) {
  CHECK_LT(SPDY3, protocol_version());
  uint8 flags = 0;
  if (continuation.end_headers()) {
    flags |= HEADERS_FLAG_END_HEADERS;
  }

  // The size of this frame, including variable-length name-value block.
  size_t size = GetContinuationMinimumSize();
  string hpack_encoding;
  if (enable_compression_) {
    GetHpackEncoder()->EncodeHeaderSet(
        continuation.name_value_block(), &hpack_encoding);
  } else {
    GetHpackEncoder()->EncodeHeaderSetWithoutCompression(
        continuation.name_value_block(), &hpack_encoding);
  }
  size += hpack_encoding.size();

  SpdyFrameBuilder builder(size, protocol_version());
  builder.BeginNewFrame(*this, CONTINUATION, flags,
      continuation.stream_id());
  DCHECK_EQ(GetContinuationMinimumSize(), builder.length());

  builder.WriteBytes(&hpack_encoding[0], hpack_encoding.size());
  return builder.take();
}

SpdyFrame* SpdyFramer::SerializeAltSvc(const SpdyAltSvcIR& altsvc_ir) {
  DCHECK_LT(SPDY3, protocol_version());

  size_t size = GetAltSvcMinimumSize();
  size += altsvc_ir.origin().length();
  string value = SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
      altsvc_ir.altsvc_vector());
  size += value.length();

  SpdyFrameBuilder builder(size, protocol_version());
  builder.BeginNewFrame(*this, ALTSVC, kNoFlags, altsvc_ir.stream_id());

  builder.WriteUInt16(altsvc_ir.origin().length());
  builder.WriteBytes(altsvc_ir.origin().data(), altsvc_ir.origin().length());
  builder.WriteBytes(value.data(), value.length());
  DCHECK_LT(GetAltSvcMinimumSize(), builder.length());
  return builder.take();
}

SpdyFrame* SpdyFramer::SerializePriority(const SpdyPriorityIR& priority) const {
  DCHECK_LT(SPDY3, protocol_version());
  size_t size = GetPrioritySize();

  SpdyFrameBuilder builder(size, protocol_version());
  builder.BeginNewFrame(*this, PRIORITY, kNoFlags, priority.stream_id());

  builder.WriteUInt32(PackStreamDependencyValues(priority.exclusive(),
                                                 priority.parent_stream_id()));
  builder.WriteUInt8(priority.weight());
  DCHECK_EQ(GetPrioritySize(), builder.length());
  return builder.take();
}

namespace {

class FrameSerializationVisitor : public SpdyFrameVisitor {
 public:
  explicit FrameSerializationVisitor(SpdyFramer* framer) : framer_(framer) {}
  ~FrameSerializationVisitor() override {}

  SpdySerializedFrame* ReleaseSerializedFrame() { return frame_.release(); }

  void VisitData(const SpdyDataIR& data) override {
    frame_.reset(framer_->SerializeData(data));
  }
  void VisitSynStream(const SpdySynStreamIR& syn_stream) override {
    frame_.reset(framer_->SerializeSynStream(syn_stream));
  }
  void VisitSynReply(const SpdySynReplyIR& syn_reply) override {
    frame_.reset(framer_->SerializeSynReply(syn_reply));
  }
  void VisitRstStream(const SpdyRstStreamIR& rst_stream) override {
    frame_.reset(framer_->SerializeRstStream(rst_stream));
  }
  void VisitSettings(const SpdySettingsIR& settings) override {
    frame_.reset(framer_->SerializeSettings(settings));
  }
  void VisitPing(const SpdyPingIR& ping) override {
    frame_.reset(framer_->SerializePing(ping));
  }
  void VisitGoAway(const SpdyGoAwayIR& goaway) override {
    frame_.reset(framer_->SerializeGoAway(goaway));
  }
  void VisitHeaders(const SpdyHeadersIR& headers) override {
    frame_.reset(framer_->SerializeHeaders(headers));
  }
  void VisitWindowUpdate(const SpdyWindowUpdateIR& window_update) override {
    frame_.reset(framer_->SerializeWindowUpdate(window_update));
  }
  void VisitBlocked(const SpdyBlockedIR& blocked) override {
    frame_.reset(framer_->SerializeBlocked(blocked));
  }
  void VisitPushPromise(const SpdyPushPromiseIR& push_promise) override {
    frame_.reset(framer_->SerializePushPromise(push_promise));
  }
  void VisitContinuation(const SpdyContinuationIR& continuation) override {
    frame_.reset(framer_->SerializeContinuation(continuation));
  }
  void VisitAltSvc(const SpdyAltSvcIR& altsvc) override {
    frame_.reset(framer_->SerializeAltSvc(altsvc));
  }
  void VisitPriority(const SpdyPriorityIR& priority) override {
    frame_.reset(framer_->SerializePriority(priority));
  }

 private:
  SpdyFramer* framer_;
  scoped_ptr<SpdySerializedFrame> frame_;
};

}  // namespace

SpdySerializedFrame* SpdyFramer::SerializeFrame(const SpdyFrameIR& frame) {
  FrameSerializationVisitor visitor(this);
  frame.Visit(&visitor);
  return visitor.ReleaseSerializedFrame();
}

size_t SpdyFramer::GetSerializedLength(const SpdyHeaderBlock& headers) {
  CHECK_GE(SPDY3, protocol_version());
  const size_t uncompressed_length =
    GetSerializedLength(protocol_version(), &headers);
  if (!enable_compression_) {
    return uncompressed_length;
  }
  z_stream* compressor = GetHeaderCompressor();
  // Since we'll be performing lots of flushes when compressing the data,
  // zlib's lower bounds may be insufficient.
  return 2 * deflateBound(compressor, uncompressed_length);
}

size_t SpdyFramer::GetNumberRequiredContinuationFrames(size_t size) {
  DCHECK_GT(protocol_version(), SPDY3);
  DCHECK_GT(size, kMaxControlFrameSize);
  size_t overflow = size - kMaxControlFrameSize;
  size_t payload_size = kMaxControlFrameSize - GetContinuationMinimumSize();
  // This is ceiling(overflow/payload_size) using integer arithmetics.
  return (overflow - 1) / payload_size + 1;
}

void SpdyFramer::WritePayloadWithContinuation(SpdyFrameBuilder* builder,
                                              const string& hpack_encoding,
                                              SpdyStreamId stream_id,
                                              SpdyFrameType type,
                                              int padding_payload_len) {
  uint8 end_flag = 0;
  uint8 flags = 0;
  if (type == HEADERS) {
    end_flag = HEADERS_FLAG_END_HEADERS;
  } else if (type == PUSH_PROMISE) {
    end_flag = PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  } else {
    DLOG(FATAL) << "CONTINUATION frames cannot be used with frame type "
                << FrameTypeToString(type);
  }

  // Write all the padding payload and as much of the data payload as possible
  // into the initial frame.
  size_t bytes_remaining = 0;
  bytes_remaining =
      hpack_encoding.size() -
      std::min(hpack_encoding.size(),
               kMaxControlFrameSize - builder->length() - padding_payload_len);
  builder->WriteBytes(&hpack_encoding[0],
                      hpack_encoding.size() - bytes_remaining);
  if (padding_payload_len > 0) {
    string padding = string(padding_payload_len, 0);
    builder->WriteBytes(padding.data(), padding.length());
  }
  if (bytes_remaining > 0) {
    builder->OverwriteLength(
        *this, kMaxControlFrameSize - GetControlFrameHeaderSize());
  }

  // Tack on CONTINUATION frames for the overflow.
  while (bytes_remaining > 0) {
    size_t bytes_to_write = std::min(
        bytes_remaining, kMaxControlFrameSize - GetContinuationMinimumSize());
    // Write CONTINUATION frame prefix.
    if (bytes_remaining == bytes_to_write) {
      flags |= end_flag;
    }
    builder->BeginNewFrame(*this, CONTINUATION, flags, stream_id);
    // Write payload fragment.
    builder->WriteBytes(
        &hpack_encoding[hpack_encoding.size() - bytes_remaining],
        bytes_to_write);
    bytes_remaining -= bytes_to_write;
  }
}

// The following compression setting are based on Brian Olson's analysis. See
// https://groups.google.com/group/spdy-dev/browse_thread/thread/dfaf498542fac792
// for more details.
#if defined(USE_SYSTEM_ZLIB)
// System zlib is not expected to have workaround for http://crbug.com/139744,
// so disable compression in that case.
// TODO(phajdan.jr): Remove the special case when it's no longer necessary.
static const int kCompressorLevel = 0;
#else  // !defined(USE_SYSTEM_ZLIB)
static const int kCompressorLevel = 9;
#endif  // !defined(USE_SYSTEM_ZLIB)
static const int kCompressorWindowSizeInBits = 11;
static const int kCompressorMemLevel = 1;

z_stream* SpdyFramer::GetHeaderCompressor() {
  if (header_compressor_.get())
    return header_compressor_.get();  // Already initialized.

  header_compressor_.reset(new z_stream);
  memset(header_compressor_.get(), 0, sizeof(z_stream));

  int success = deflateInit2(header_compressor_.get(),
                             kCompressorLevel,
                             Z_DEFLATED,
                             kCompressorWindowSizeInBits,
                             kCompressorMemLevel,
                             Z_DEFAULT_STRATEGY);
  if (success == Z_OK) {
    const char* dictionary = (protocol_version() <= SPDY2) ?
        kV2Dictionary : kV3Dictionary;
    const int dictionary_size = (protocol_version() <= SPDY2) ?
        kV2DictionarySize : kV3DictionarySize;
    success = deflateSetDictionary(header_compressor_.get(),
                                   reinterpret_cast<const Bytef*>(dictionary),
                                   dictionary_size);
  }
  if (success != Z_OK) {
    LOG(WARNING) << "deflateSetDictionary failure: " << success;
    header_compressor_.reset(NULL);
    return NULL;
  }
  return header_compressor_.get();
}

z_stream* SpdyFramer::GetHeaderDecompressor() {
  if (header_decompressor_.get())
    return header_decompressor_.get();  // Already initialized.

  header_decompressor_.reset(new z_stream);
  memset(header_decompressor_.get(), 0, sizeof(z_stream));

  int success = inflateInit(header_decompressor_.get());
  if (success != Z_OK) {
    LOG(WARNING) << "inflateInit failure: " << success;
    header_decompressor_.reset(NULL);
    return NULL;
  }
  return header_decompressor_.get();
}

HpackEncoder* SpdyFramer::GetHpackEncoder() {
  DCHECK_LT(SPDY3, protocol_version());
  if (hpack_encoder_.get() == nullptr) {
    hpack_encoder_.reset(new HpackEncoder(ObtainHpackHuffmanTable()));
  }
  return hpack_encoder_.get();
}

HpackDecoder* SpdyFramer::GetHpackDecoder() {
  DCHECK_LT(SPDY3, protocol_version());
  if (hpack_decoder_.get() == nullptr) {
    hpack_decoder_.reset(new HpackDecoder(ObtainHpackHuffmanTable()));
  }
  return hpack_decoder_.get();
}

uint8 SpdyFramer::MapPriorityToWeight(SpdyPriority priority) {
  const float kSteps = 255.9f / 7.f;
  return static_cast<uint8>(kSteps * (7.f - priority));
}

SpdyPriority SpdyFramer::MapWeightToPriority(uint8 weight) {
  const float kSteps = 255.9f / 7.f;
  return static_cast<SpdyPriority>(7.f - weight / kSteps);
}

// Incrementally decompress the control frame's header block, feeding the
// result to the visitor in chunks. Continue this until the visitor
// indicates that it cannot process any more data, or (more commonly) we
// run out of data to deliver.
bool SpdyFramer::IncrementallyDecompressControlFrameHeaderData(
    SpdyStreamId stream_id,
    const char* data,
    size_t len) {
  // Get a decompressor or set error.
  z_stream* decomp = GetHeaderDecompressor();
  if (decomp == NULL) {
    LOG(DFATAL) << "Couldn't get decompressor for handling compressed headers.";
    set_error(SPDY_DECOMPRESS_FAILURE);
    return false;
  }

  bool processed_successfully = true;
  char buffer[kHeaderDataChunkMaxSize];

  decomp->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data));
  decomp->avail_in = len;
  // If we get a SYN_STREAM/SYN_REPLY/HEADERS frame with stream ID zero, we
  // signal an error back in ProcessControlFrameBeforeHeaderBlock.  So if we've
  // reached this method successfully, stream_id should be nonzero.
  DCHECK_LT(0u, stream_id);
  while (decomp->avail_in > 0 && processed_successfully) {
    decomp->next_out = reinterpret_cast<Bytef*>(buffer);
    decomp->avail_out = arraysize(buffer);

    int rv = inflate(decomp, Z_SYNC_FLUSH);
    if (rv == Z_NEED_DICT) {
      const char* dictionary = (protocol_version() <= SPDY2) ? kV2Dictionary
                                                             : kV3Dictionary;
      const int dictionary_size = (protocol_version() <= SPDY2) ?
          kV2DictionarySize : kV3DictionarySize;
      const DictionaryIds& ids = g_dictionary_ids.Get();
      const uLong dictionary_id = (protocol_version() <= SPDY2) ?
          ids.v2_dictionary_id : ids.v3_dictionary_id;
      // Need to try again with the right dictionary.
      if (decomp->adler == dictionary_id) {
        rv = inflateSetDictionary(decomp,
                                  reinterpret_cast<const Bytef*>(dictionary),
                                  dictionary_size);
        if (rv == Z_OK)
          rv = inflate(decomp, Z_SYNC_FLUSH);
      }
    }

    // Inflate will generate a Z_BUF_ERROR if it runs out of input
    // without producing any output.  The input is consumed and
    // buffered internally by zlib so we can detect this condition by
    // checking if avail_in is 0 after the call to inflate.
    bool input_exhausted = ((rv == Z_BUF_ERROR) && (decomp->avail_in == 0));
    if ((rv == Z_OK) || input_exhausted) {
      size_t decompressed_len = arraysize(buffer) - decomp->avail_out;
      if (decompressed_len > 0) {
        processed_successfully = visitor_->OnControlFrameHeaderData(
            stream_id, buffer, decompressed_len);
      }
      if (!processed_successfully) {
        // Assume that the problem was the header block was too large for the
        // visitor.
        set_error(SPDY_CONTROL_PAYLOAD_TOO_LARGE);
      }
    } else {
      DLOG(WARNING) << "inflate failure: " << rv << " " << len;
      set_error(SPDY_DECOMPRESS_FAILURE);
      processed_successfully = false;
    }
  }
  return processed_successfully;
}

bool SpdyFramer::IncrementallyDeliverControlFrameHeaderData(
    SpdyStreamId stream_id, const char* data, size_t len) {
  bool read_successfully = true;
  while (read_successfully && len > 0) {
    size_t bytes_to_deliver = std::min(len, kHeaderDataChunkMaxSize);
    read_successfully = visitor_->OnControlFrameHeaderData(stream_id, data,
                                                           bytes_to_deliver);
    data += bytes_to_deliver;
    len -= bytes_to_deliver;
    if (!read_successfully) {
      // Assume that the problem was the header block was too large for the
      // visitor.
      set_error(SPDY_CONTROL_PAYLOAD_TOO_LARGE);
    }
  }
  return read_successfully;
}

void SpdyFramer::UpdateHeaderTableSizeSetting(uint32 value) {
  header_table_size_bound_ = value;
  GetHpackEncoder()->ApplyHeaderTableSizeSetting(value);
  GetHpackDecoder()->ApplyHeaderTableSizeSetting(value);
}

// Return size bound of the header compression table.
size_t SpdyFramer::header_table_size_bound() const {
  return header_table_size_bound_;
}

void SpdyFramer::SerializeNameValueBlockWithoutCompression(
    SpdyFrameBuilder* builder,
    const SpdyNameValueBlock& name_value_block) const {
  // Serialize number of headers.
  if (protocol_version() <= SPDY2) {
    builder->WriteUInt16(static_cast<uint16>(name_value_block.size()));
  } else {
    builder->WriteUInt32(name_value_block.size());
  }

  // Serialize each header.
  for (SpdyHeaderBlock::const_iterator it = name_value_block.begin();
       it != name_value_block.end();
       ++it) {
    if (protocol_version() <= SPDY2) {
      builder->WriteStringPiece16(it->first);
      builder->WriteStringPiece16(it->second);
    } else {
      builder->WriteStringPiece32(it->first);
      builder->WriteStringPiece32(it->second);
    }
  }
}

void SpdyFramer::SerializeNameValueBlock(
    SpdyFrameBuilder* builder,
    const SpdyFrameWithNameValueBlockIR& frame) {
  CHECK_GE(SPDY3, protocol_version());
  if (!enable_compression_) {
    return SerializeNameValueBlockWithoutCompression(builder,
                                                     frame.name_value_block());
  }

  // First build an uncompressed version to be fed into the compressor.
  const size_t uncompressed_len = GetSerializedLength(
      protocol_version(), &(frame.name_value_block()));
  SpdyFrameBuilder uncompressed_builder(uncompressed_len, protocol_version());
  SerializeNameValueBlockWithoutCompression(&uncompressed_builder,
                                            frame.name_value_block());
  scoped_ptr<SpdyFrame> uncompressed_payload(uncompressed_builder.take());

  z_stream* compressor = GetHeaderCompressor();
  if (!compressor) {
    LOG(DFATAL) << "Could not obtain compressor.";
    return;
  }
  // Create an output frame.
  // Since we'll be performing lots of flushes when compressing the data,
  // zlib's lower bounds may be insufficient.
  //
  // TODO(akalin): Avoid the duplicate calculation with
  // GetSerializedLength(const SpdyHeaderBlock&).
  const int compressed_max_size =
      2 * deflateBound(compressor, uncompressed_len);

  // TODO(phajdan.jr): Clean up after we no longer need
  // to workaround http://crbug.com/139744.
#if defined(USE_SYSTEM_ZLIB)
  compressor->next_in = reinterpret_cast<Bytef*>(uncompressed_payload->data());
  compressor->avail_in = uncompressed_len;
#endif  // defined(USE_SYSTEM_ZLIB)
  compressor->next_out = reinterpret_cast<Bytef*>(
      builder->GetWritableBuffer(compressed_max_size));
  compressor->avail_out = compressed_max_size;

  // TODO(phajdan.jr): Clean up after we no longer need
  // to workaround http://crbug.com/139744.
#if defined(USE_SYSTEM_ZLIB)
  int rv = deflate(compressor, Z_SYNC_FLUSH);
  if (rv != Z_OK) {  // How can we know that it compressed everything?
    // This shouldn't happen, right?
    LOG(WARNING) << "deflate failure: " << rv;
    // TODO(akalin): Upstream this return.
    return;
  }
#else
  WriteHeaderBlockToZ(&frame.name_value_block(), compressor);
#endif  // defined(USE_SYSTEM_ZLIB)

  int compressed_size = compressed_max_size - compressor->avail_out;
  builder->Seek(compressed_size);
  builder->RewriteLength(*this);
}

}  // namespace net
