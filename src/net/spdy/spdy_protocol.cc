// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_protocol.h"

#include "net/spdy/spdy_bug_tracker.h"

namespace net {

bool SpdyConstants::IsValidFrameType(SpdyMajorVersion version,
                                     int frame_type_field) {
  switch (version) {
    case SPDY3:
      // SYN_STREAM is the first valid frame.
      if (frame_type_field < SerializeFrameType(version, SYN_STREAM)) {
        return false;
      }

      // WINDOW_UPDATE is the last valid frame.
      if (frame_type_field > SerializeFrameType(version, WINDOW_UPDATE)) {
        return false;
      }

      return true;
    case HTTP2:
      // Check for recognized extensions.
      if (frame_type_field == SerializeFrameType(version, ALTSVC) ||
          frame_type_field == SerializeFrameType(version, BLOCKED)) {
        return true;
      }

      // DATA is the first valid frame.
      if (frame_type_field < SerializeFrameType(version, DATA)) {
        return false;
      }

      // CONTINUATION is the last valid frame.
      if (frame_type_field > SerializeFrameType(version, CONTINUATION)) {
        return false;
      }

      return true;
  }

  SPDY_BUG << "Unhandled SPDY version " << version;
  return false;
}

SpdyFrameType SpdyConstants::ParseFrameType(SpdyMajorVersion version,
                                            int frame_type_field) {
  switch (version) {
    case SPDY3:
      switch (frame_type_field) {
        case 1:
          return SYN_STREAM;
        case 2:
          return SYN_REPLY;
        case 3:
          return RST_STREAM;
        case 4:
          return SETTINGS;
        case 6:
          return PING;
        case 7:
          return GOAWAY;
        case 8:
          return HEADERS;
        case 9:
          return WINDOW_UPDATE;
      }
      break;
    case HTTP2:
      switch (frame_type_field) {
        case 0:
          return DATA;
        case 1:
          return HEADERS;
        case 2:
          return PRIORITY;
        case 3:
          return RST_STREAM;
        case 4:
          return SETTINGS;
        case 5:
          return PUSH_PROMISE;
        case 6:
          return PING;
        case 7:
          return GOAWAY;
        case 8:
          return WINDOW_UPDATE;
        case 9:
          return CONTINUATION;
        case 10:
          return ALTSVC;
        case 11:
          return BLOCKED;
      }
      break;
  }

  SPDY_BUG << "Unhandled frame type " << frame_type_field;
  return DATA;
}

int SpdyConstants::SerializeFrameType(SpdyMajorVersion version,
                                      SpdyFrameType frame_type) {
  switch (version) {
    case SPDY3:
      switch (frame_type) {
        case SYN_STREAM:
          return 1;
        case SYN_REPLY:
          return 2;
        case RST_STREAM:
          return 3;
        case SETTINGS:
          return 4;
        case PING:
          return 6;
        case GOAWAY:
          return 7;
        case HEADERS:
          return 8;
        case WINDOW_UPDATE:
          return 9;
        default:
          SPDY_BUG << "Serializing unhandled frame type " << frame_type;
          return -1;
      }
    case HTTP2:
      switch (frame_type) {
        case DATA:
          return 0;
        case HEADERS:
          return 1;
        case PRIORITY:
          return 2;
        case RST_STREAM:
          return 3;
        case SETTINGS:
          return 4;
        case PUSH_PROMISE:
          return 5;
        case PING:
          return 6;
        case GOAWAY:
          return 7;
        case WINDOW_UPDATE:
          return 8;
        case CONTINUATION:
          return 9;
        // ALTSVC and BLOCKED are extensions.
        case ALTSVC:
          return 10;
        case BLOCKED:
          return 11;
        default:
          SPDY_BUG << "Serializing unhandled frame type " << frame_type;
          return -1;
      }
  }

  SPDY_BUG << "Unhandled SPDY version " << version;
  return -1;
}

int SpdyConstants::DataFrameType(SpdyMajorVersion version) {
  switch (version) {
    case SPDY3:
      return 0;
    case HTTP2:
      return SerializeFrameType(version, DATA);
  }

  SPDY_BUG << "Unhandled SPDY version " << version;
  return 0;
}

bool SpdyConstants::IsValidHTTP2FrameStreamId(
    SpdyStreamId current_frame_stream_id,
    SpdyFrameType frame_type_field) {
  if (current_frame_stream_id == 0) {
    switch (frame_type_field) {
      case DATA:
      case HEADERS:
      case PRIORITY:
      case RST_STREAM:
      case CONTINUATION:
      case PUSH_PROMISE:
        // These frame types must specify a stream
        return false;
      default:
        return true;
    }
  } else {
    switch (frame_type_field) {
      case GOAWAY:
      case SETTINGS:
      case PING:
        // These frame types must not specify a stream
        return false;
      default:
        return true;
    }
  }
}

bool SpdyConstants::IsValidSettingId(SpdyMajorVersion version,
                                     int setting_id_field) {
  switch (version) {
    case SPDY3:
      // UPLOAD_BANDWIDTH is the first valid setting id.
      if (setting_id_field <
          SerializeSettingId(version, SETTINGS_UPLOAD_BANDWIDTH)) {
        return false;
      }

      // INITIAL_WINDOW_SIZE is the last valid setting id.
      if (setting_id_field >
          SerializeSettingId(version, SETTINGS_INITIAL_WINDOW_SIZE)) {
        return false;
      }

      return true;
    case HTTP2:
      // HEADER_TABLE_SIZE is the first valid setting id.
      if (setting_id_field <
          SerializeSettingId(version, SETTINGS_HEADER_TABLE_SIZE)) {
        return false;
      }

      // MAX_HEADER_LIST_SIZE is the last valid setting id.
      if (setting_id_field >
          SerializeSettingId(version, SETTINGS_MAX_HEADER_LIST_SIZE)) {
        return false;
      }

      return true;
  }

  SPDY_BUG << "Unhandled SPDY version " << version;
  return false;
}

SpdySettingsIds SpdyConstants::ParseSettingId(SpdyMajorVersion version,
                                              int setting_id_field) {
  switch (version) {
    case SPDY3:
      switch (setting_id_field) {
        case 1:
          return SETTINGS_UPLOAD_BANDWIDTH;
        case 2:
          return SETTINGS_DOWNLOAD_BANDWIDTH;
        case 3:
          return SETTINGS_ROUND_TRIP_TIME;
        case 4:
          return SETTINGS_MAX_CONCURRENT_STREAMS;
        case 5:
          return SETTINGS_CURRENT_CWND;
        case 6:
          return SETTINGS_DOWNLOAD_RETRANS_RATE;
        case 7:
          return SETTINGS_INITIAL_WINDOW_SIZE;
      }
      break;
    case HTTP2:
      switch (setting_id_field) {
        case 1:
          return SETTINGS_HEADER_TABLE_SIZE;
        case 2:
          return SETTINGS_ENABLE_PUSH;
        case 3:
          return SETTINGS_MAX_CONCURRENT_STREAMS;
        case 4:
          return SETTINGS_INITIAL_WINDOW_SIZE;
        case 5:
          return SETTINGS_MAX_FRAME_SIZE;
        case 6:
          return SETTINGS_MAX_HEADER_LIST_SIZE;
      }
      break;
  }

  SPDY_BUG << "Unhandled setting ID " << setting_id_field;
  return SETTINGS_UPLOAD_BANDWIDTH;
}

int SpdyConstants::SerializeSettingId(SpdyMajorVersion version,
                                       SpdySettingsIds id) {
  switch (version) {
    case SPDY3:
      switch (id) {
        case SETTINGS_UPLOAD_BANDWIDTH:
          return 1;
        case SETTINGS_DOWNLOAD_BANDWIDTH:
          return 2;
        case SETTINGS_ROUND_TRIP_TIME:
          return 3;
        case SETTINGS_MAX_CONCURRENT_STREAMS:
          return 4;
        case SETTINGS_CURRENT_CWND:
          return 5;
        case SETTINGS_DOWNLOAD_RETRANS_RATE:
          return 6;
        case SETTINGS_INITIAL_WINDOW_SIZE:
          return 7;
        default:
          SPDY_BUG << "Serializing unhandled setting id " << id;
          return -1;
      }
    case HTTP2:
      switch (id) {
        case SETTINGS_HEADER_TABLE_SIZE:
          return 1;
        case SETTINGS_ENABLE_PUSH:
          return 2;
        case SETTINGS_MAX_CONCURRENT_STREAMS:
          return 3;
        case SETTINGS_INITIAL_WINDOW_SIZE:
          return 4;
        case SETTINGS_MAX_FRAME_SIZE:
          return 5;
        case SETTINGS_MAX_HEADER_LIST_SIZE:
          return 6;
        default:
          SPDY_BUG << "Serializing unhandled setting id " << id;
          return -1;
      }
  }
  SPDY_BUG << "Unhandled SPDY version " << version;
  return -1;
}

bool SpdyConstants::IsValidRstStreamStatus(SpdyMajorVersion version,
                                           int rst_stream_status_field) {
  switch (version) {
    case SPDY3:
      // PROTOCOL_ERROR is the valid first status code.
      if (rst_stream_status_field <
          SerializeRstStreamStatus(version, RST_STREAM_PROTOCOL_ERROR)) {
        return false;
      }

      // FRAME_TOO_LARGE is the valid last status code.
      if (rst_stream_status_field >
          SerializeRstStreamStatus(version, RST_STREAM_FRAME_TOO_LARGE)) {
        return false;
      }

      return true;
    case HTTP2:
      // NO_ERROR is the first valid status code.
      if (rst_stream_status_field <
          SerializeRstStreamStatus(version, RST_STREAM_PROTOCOL_ERROR)) {
        return false;
      }

      // TODO(hkhalil): Omit COMPRESSION_ERROR and SETTINGS_TIMEOUT
      /*
      // This works because GOAWAY and RST_STREAM share a namespace.
      if (rst_stream_status_field ==
          SerializeGoAwayStatus(version, GOAWAY_COMPRESSION_ERROR) ||
          rst_stream_status_field ==
          SerializeGoAwayStatus(version, GOAWAY_SETTINGS_TIMEOUT)) {
        return false;
      }
      */

      // HTTP_1_1_REQUIRED is the last valid status code.
      if (rst_stream_status_field >
          SerializeRstStreamStatus(version, RST_STREAM_HTTP_1_1_REQUIRED)) {
        return false;
      }

      return true;
  }
  SPDY_BUG << "Unhandled SPDY version " << version;
  return false;
}

SpdyRstStreamStatus SpdyConstants::ParseRstStreamStatus(
    SpdyMajorVersion version,
    int rst_stream_status_field) {
  switch (version) {
    case SPDY3:
      switch (rst_stream_status_field) {
        case 1:
          return RST_STREAM_PROTOCOL_ERROR;
        case 2:
          return RST_STREAM_INVALID_STREAM;
        case 3:
          return RST_STREAM_REFUSED_STREAM;
        case 4:
          return RST_STREAM_UNSUPPORTED_VERSION;
        case 5:
          return RST_STREAM_CANCEL;
        case 6:
          return RST_STREAM_INTERNAL_ERROR;
        case 7:
          return RST_STREAM_FLOW_CONTROL_ERROR;
        case 8:
          return RST_STREAM_STREAM_IN_USE;
        case 9:
          return RST_STREAM_STREAM_ALREADY_CLOSED;
        case 11:
          return RST_STREAM_FRAME_TOO_LARGE;
      }
      break;
    case HTTP2:
      switch (rst_stream_status_field) {
        case 1:
          return RST_STREAM_PROTOCOL_ERROR;
        case 2:
          return RST_STREAM_INTERNAL_ERROR;
        case 3:
          return RST_STREAM_FLOW_CONTROL_ERROR;
        case 5:
          return RST_STREAM_STREAM_CLOSED;
        case 6:
          return RST_STREAM_FRAME_SIZE_ERROR;
        case 7:
          return RST_STREAM_REFUSED_STREAM;
        case 8:
          return RST_STREAM_CANCEL;
        case 10:
          return RST_STREAM_CONNECT_ERROR;
        case 11:
          return RST_STREAM_ENHANCE_YOUR_CALM;
        case 12:
          return RST_STREAM_INADEQUATE_SECURITY;
        case 13:
          return RST_STREAM_HTTP_1_1_REQUIRED;
      }
      break;
  }

  SPDY_BUG << "Invalid RST_STREAM status " << rst_stream_status_field;
  return RST_STREAM_PROTOCOL_ERROR;
}

int SpdyConstants::SerializeRstStreamStatus(
    SpdyMajorVersion version,
    SpdyRstStreamStatus rst_stream_status) {
  switch (version) {
    case SPDY3:
      switch (rst_stream_status) {
        case RST_STREAM_PROTOCOL_ERROR:
          return 1;
        case RST_STREAM_INVALID_STREAM:
          return 2;
        case RST_STREAM_REFUSED_STREAM:
          return 3;
        case RST_STREAM_UNSUPPORTED_VERSION:
          return 4;
        case RST_STREAM_CANCEL:
          return 5;
        case RST_STREAM_INTERNAL_ERROR:
          return 6;
        case RST_STREAM_FLOW_CONTROL_ERROR:
          return 7;
        case RST_STREAM_STREAM_IN_USE:
          return 8;
        case RST_STREAM_STREAM_ALREADY_CLOSED:
          return 9;
        case RST_STREAM_FRAME_TOO_LARGE:
          return 11;
        default:
          SPDY_BUG << "Unhandled RST_STREAM status " << rst_stream_status;
          return -1;
      }
    case HTTP2:
      switch (rst_stream_status) {
        case RST_STREAM_PROTOCOL_ERROR:
          return 1;
        case RST_STREAM_INTERNAL_ERROR:
          return 2;
        case RST_STREAM_FLOW_CONTROL_ERROR:
          return 3;
        case RST_STREAM_STREAM_CLOSED:
          return 5;
        case RST_STREAM_FRAME_SIZE_ERROR:
          return 6;
        case RST_STREAM_REFUSED_STREAM:
          return 7;
        case RST_STREAM_CANCEL:
          return 8;
        case RST_STREAM_CONNECT_ERROR:
          return 10;
        case RST_STREAM_ENHANCE_YOUR_CALM:
          return 11;
        case RST_STREAM_INADEQUATE_SECURITY:
          return 12;
        case RST_STREAM_HTTP_1_1_REQUIRED:
          return 13;
        default:
          SPDY_BUG << "Unhandled RST_STREAM status " << rst_stream_status;
          return -1;
      }
  }
  SPDY_BUG << "Unhandled SPDY version " << version;
  return -1;
}

bool SpdyConstants::IsValidGoAwayStatus(SpdyMajorVersion version,
                                        int goaway_status_field) {
  switch (version) {
    case SPDY3:
      // GOAWAY_OK is the first valid status.
      if (goaway_status_field < SerializeGoAwayStatus(version, GOAWAY_OK)) {
        return false;
      }

      // GOAWAY_INTERNAL_ERROR is the last valid status.
      if (goaway_status_field > SerializeGoAwayStatus(version,
                                                      GOAWAY_INTERNAL_ERROR)) {
        return false;
      }

      return true;
    case HTTP2:
      // GOAWAY_NO_ERROR is the first valid status.
      if (goaway_status_field < SerializeGoAwayStatus(version,
                                                      GOAWAY_NO_ERROR)) {
        return false;
      }

      // GOAWAY_HTTP_1_1_REQUIRED is the last valid status.
      if (goaway_status_field >
          SerializeGoAwayStatus(version, GOAWAY_HTTP_1_1_REQUIRED)) {
        return false;
      }

      return true;
  }
  SPDY_BUG << "Unknown SpdyMajorVersion " << version;
  return false;
}

SpdyGoAwayStatus SpdyConstants::ParseGoAwayStatus(SpdyMajorVersion version,
                                                  int goaway_status_field) {
  switch (version) {
    case SPDY3:
      switch (goaway_status_field) {
        case 0:
          return GOAWAY_OK;
        case 1:
          return GOAWAY_PROTOCOL_ERROR;
        case 2:
          return GOAWAY_INTERNAL_ERROR;
      }
      break;
    case HTTP2:
      switch (goaway_status_field) {
        case 0:
          return GOAWAY_NO_ERROR;
        case 1:
          return GOAWAY_PROTOCOL_ERROR;
        case 2:
          return GOAWAY_INTERNAL_ERROR;
        case 3:
          return GOAWAY_FLOW_CONTROL_ERROR;
        case 4:
          return GOAWAY_SETTINGS_TIMEOUT;
        case 5:
          return GOAWAY_STREAM_CLOSED;
        case 6:
          return GOAWAY_FRAME_SIZE_ERROR;
        case 7:
          return GOAWAY_REFUSED_STREAM;
        case 8:
          return GOAWAY_CANCEL;
        case 9:
          return GOAWAY_COMPRESSION_ERROR;
        case 10:
          return GOAWAY_CONNECT_ERROR;
        case 11:
          return GOAWAY_ENHANCE_YOUR_CALM;
        case 12:
          return GOAWAY_INADEQUATE_SECURITY;
        case 13:
          return GOAWAY_HTTP_1_1_REQUIRED;
      }
      break;
  }

  SPDY_BUG << "Unhandled GOAWAY status " << goaway_status_field;
  return GOAWAY_PROTOCOL_ERROR;
}

int SpdyConstants::SerializeGoAwayStatus(SpdyMajorVersion version,
                                         SpdyGoAwayStatus status) {
  switch (version) {
    case SPDY3:
      // TODO(jgraettinger): Merge this back to server-side.
      switch (status) {
        case GOAWAY_NO_ERROR:
          return 0;
        case GOAWAY_PROTOCOL_ERROR:
        case GOAWAY_INTERNAL_ERROR:
        case GOAWAY_FLOW_CONTROL_ERROR:
        case GOAWAY_SETTINGS_TIMEOUT:
        case GOAWAY_STREAM_CLOSED:
        case GOAWAY_FRAME_SIZE_ERROR:
        case GOAWAY_REFUSED_STREAM:
        case GOAWAY_CANCEL:
        case GOAWAY_COMPRESSION_ERROR:
        case GOAWAY_CONNECT_ERROR:
        case GOAWAY_ENHANCE_YOUR_CALM:
        case GOAWAY_INADEQUATE_SECURITY:
        case GOAWAY_HTTP_1_1_REQUIRED:
          return 1;  // PROTOCOL_ERROR.
        default:
          SPDY_BUG << "Serializing unhandled GOAWAY status " << status;
          return -1;
      }
    case HTTP2:
      switch (status) {
        case GOAWAY_NO_ERROR:
          return 0;
        case GOAWAY_PROTOCOL_ERROR:
          return 1;
        case GOAWAY_INTERNAL_ERROR:
          return 2;
        case GOAWAY_FLOW_CONTROL_ERROR:
          return 3;
        case GOAWAY_SETTINGS_TIMEOUT:
          return 4;
        case GOAWAY_STREAM_CLOSED:
          return 5;
        case GOAWAY_FRAME_SIZE_ERROR:
          return 6;
        case GOAWAY_REFUSED_STREAM:
          return 7;
        case GOAWAY_CANCEL:
          return 8;
        case GOAWAY_COMPRESSION_ERROR:
          return 9;
        case GOAWAY_CONNECT_ERROR:
          return 10;
        case GOAWAY_ENHANCE_YOUR_CALM:
          return 11;
        case GOAWAY_INADEQUATE_SECURITY:
          return 12;
        case GOAWAY_HTTP_1_1_REQUIRED:
          return 13;
        default:
          SPDY_BUG << "Serializing unhandled GOAWAY status " << status;
          return -1;
      }
  }
  SPDY_BUG << "Unknown SpdyMajorVersion " << version;
  return -1;
}

size_t SpdyConstants::GetDataFrameMinimumSize(SpdyMajorVersion version) {
  switch (version) {
    case SPDY3:
      return 8;
    case HTTP2:
      return 9;
  }
  SPDY_BUG << "Unhandled SPDY version.";
  return 0;
}

size_t SpdyConstants::GetControlFrameHeaderSize(SpdyMajorVersion version) {
  switch (version) {
    case SPDY3:
      return 8;
    case HTTP2:
      return 9;
  }
  SPDY_BUG << "Unhandled SPDY version.";
  return 0;
}

size_t SpdyConstants::GetPrefixLength(SpdyFrameType type,
                                      SpdyMajorVersion version) {
  if (type != DATA) {
     return GetControlFrameHeaderSize(version);
  } else {
     return GetDataFrameMinimumSize(version);
  }
}

size_t SpdyConstants::GetFrameMaximumSize(SpdyMajorVersion version) {
  if (version == SPDY3) {
    // 24-bit length field plus eight-byte frame header.
    return ((1 << 24) - 1) + 8;
  } else {
    // Max payload of 2^14 plus nine-byte frame header.
    // TODO(mlavan): In HTTP/2 this is actually not a constant;
    // payload size can be set using the MAX_FRAME_SIZE setting to
    // anything between 1 << 14 and (1 << 24) - 1
    return (1 << 14) + 9;
  }
}

size_t SpdyConstants::GetSizeOfSizeField() {
  return sizeof(uint32_t);
}

size_t SpdyConstants::GetSettingSize(SpdyMajorVersion version) {
  return version == SPDY3 ? 8 : 6;
}

int32_t SpdyConstants::GetInitialStreamWindowSize(SpdyMajorVersion version) {
  return (version == SPDY3) ? (64 * 1024) : (64 * 1024 - 1);
}

int32_t SpdyConstants::GetInitialSessionWindowSize(SpdyMajorVersion version) {
  return (version == SPDY3) ? (64 * 1024) : (64 * 1024 - 1);
}

std::string SpdyConstants::GetVersionString(SpdyMajorVersion version) {
  switch (version) {
    case SPDY3:
      return "spdy/3";
    case HTTP2:
      return "h2";
    default:
      SPDY_BUG << "Unsupported SPDY major version: " << version;
      return "spdy/3";
  }
}

SpdyFrameWithHeaderBlockIR::SpdyFrameWithHeaderBlockIR(SpdyStreamId stream_id)
    : SpdyFrameWithFinIR(stream_id) {}

SpdyFrameWithHeaderBlockIR::~SpdyFrameWithHeaderBlockIR() {}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id, base::StringPiece data)
    : SpdyFrameWithFinIR(stream_id), padded_(false), padding_payload_len_(0) {
  SetDataDeep(data);
}

SpdyDataIR::SpdyDataIR(SpdyStreamId stream_id)
    : SpdyFrameWithFinIR(stream_id), padded_(false), padding_payload_len_(0) {}

SpdyDataIR::~SpdyDataIR() {}

void SpdyDataIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitData(*this);
}

void SpdySynStreamIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSynStream(*this);
}

void SpdySynReplyIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSynReply(*this);
}

SpdyRstStreamIR::SpdyRstStreamIR(SpdyStreamId stream_id,
                                 SpdyRstStreamStatus status)
    : SpdyFrameWithStreamIdIR(stream_id) {
  set_status(status);
}

SpdyRstStreamIR::~SpdyRstStreamIR() {}

void SpdyRstStreamIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitRstStream(*this);
}

SpdySettingsIR::SpdySettingsIR()
    : clear_settings_(false),
      is_ack_(false) {}

SpdySettingsIR::~SpdySettingsIR() {}

void SpdySettingsIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitSettings(*this);
}

void SpdyPingIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPing(*this);
}

SpdyGoAwayIR::SpdyGoAwayIR(SpdyStreamId last_good_stream_id,
                           SpdyGoAwayStatus status,
                           base::StringPiece description)
    : description_(description) {
      set_last_good_stream_id(last_good_stream_id);
  set_status(status);
}

SpdyGoAwayIR::~SpdyGoAwayIR() {}

void SpdyGoAwayIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitGoAway(*this);
}

void SpdyHeadersIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitHeaders(*this);
}

void SpdyWindowUpdateIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitWindowUpdate(*this);
}

void SpdyBlockedIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitBlocked(*this);
}

void SpdyPushPromiseIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPushPromise(*this);
}

void SpdyContinuationIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitContinuation(*this);
}

SpdyAltSvcIR::SpdyAltSvcIR(SpdyStreamId stream_id)
    : SpdyFrameWithStreamIdIR(stream_id) {
}

SpdyAltSvcIR::~SpdyAltSvcIR() {
}

void SpdyAltSvcIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitAltSvc(*this);
}

void SpdyPriorityIR::Visit(SpdyFrameVisitor* visitor) const {
  return visitor->VisitPriority(*this);
}

}  // namespace net
