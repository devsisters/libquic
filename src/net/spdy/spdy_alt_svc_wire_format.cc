// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_alt_svc_wire_format.h"

#include <algorithm>
#include <limits>
#include <string>

#include "base/logging.h"
#include "base/strings/stringprintf.h"

namespace net {

using base::StringPiece;

namespace {

template <class T>
bool ParsePositiveIntegerImpl(StringPiece::const_iterator c,
                              StringPiece::const_iterator end,
                              T* value) {
  *value = 0;
  for (; c != end && isdigit(*c); ++c) {
    if (*value > std::numeric_limits<T>::max() / 10) {
      return false;
    }
    *value *= 10;
    if (*value > std::numeric_limits<T>::max() - (*c - '0')) {
      return false;
    }
    *value += *c - '0';
  }
  return (c == end && *value > 0);
}

}  // namespace

SpdyAltSvcWireFormat::AlternativeService::AlternativeService() {}

SpdyAltSvcWireFormat::AlternativeService::AlternativeService(
    const std::string& protocol_id,
    const std::string& host,
    uint16_t port,
    uint32_t max_age,
    VersionVector version)
    : protocol_id(protocol_id),
      host(host),
      port(port),
      max_age(max_age),
      version(version) {}

SpdyAltSvcWireFormat::AlternativeService::~AlternativeService() {}

SpdyAltSvcWireFormat::AlternativeService::AlternativeService(
    const AlternativeService& other) = default;

// static
bool SpdyAltSvcWireFormat::ParseHeaderFieldValue(
    StringPiece value,
    AlternativeServiceVector* altsvc_vector) {
  // Empty value is invalid according to the specification.
  if (value.empty()) {
    return false;
  }
  altsvc_vector->clear();
  if (value == StringPiece("clear")) {
    return true;
  }
  StringPiece::const_iterator c = value.begin();
  while (c != value.end()) {
    // Parse protocol-id.
    StringPiece::const_iterator percent_encoded_protocol_id_end =
        std::find(c, value.end(), '=');
    std::string protocol_id;
    if (percent_encoded_protocol_id_end == c ||
        !PercentDecode(c, percent_encoded_protocol_id_end, &protocol_id)) {
      return false;
    }
    c = percent_encoded_protocol_id_end;
    if (c == value.end()) {
      return false;
    }
    // Parse alt-authority.
    DCHECK_EQ('=', *c);
    ++c;
    if (c == value.end() || *c != '"') {
      return false;
    }
    ++c;
    StringPiece::const_iterator alt_authority_begin = c;
    for (; c != value.end() && *c != '"'; ++c) {
      // Decode backslash encoding.
      if (*c != '\\') {
        continue;
      }
      ++c;
      if (c == value.end()) {
        return false;
      }
    }
    if (c == alt_authority_begin || c == value.end()) {
      return false;
    }
    DCHECK_EQ('"', *c);
    std::string host;
    uint16_t port;
    if (!ParseAltAuthority(alt_authority_begin, c, &host, &port)) {
      return false;
    }
    ++c;
    // Parse parameters.
    uint32_t max_age = 86400;
    VersionVector version;
    StringPiece::const_iterator parameters_end = std::find(c, value.end(), ',');
    while (c != parameters_end) {
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end) {
        break;
      }
      if (*c != ';') {
        return false;
      }
      ++c;
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end) {
        break;
      }
      std::string parameter_name;
      for (; c != parameters_end && *c != '=' && *c != ' ' && *c != '\t'; ++c) {
        parameter_name.push_back(tolower(*c));
      }
      SkipWhiteSpace(&c, parameters_end);
      if (c == parameters_end || *c != '=') {
        return false;
      }
      ++c;
      SkipWhiteSpace(&c, parameters_end);
      StringPiece::const_iterator parameter_value_begin = c;
      for (; c != parameters_end && *c != ';' && *c != ' ' && *c != '\t'; ++c) {
      }
      if (c == parameter_value_begin) {
        return false;
      }
      if (parameter_name.compare("ma") == 0) {
        if (!ParsePositiveInteger32(parameter_value_begin, c, &max_age)) {
          return false;
        }
      } else if (parameter_name.compare("v") == 0) {
        // Version is a comma separated list of positive integers enclosed in
        // quotation marks.  Since it can contain commas, which are not
        // delineating alternative service entries, |parameters_end| and |c| can
        // be invalid.
        if (*parameter_value_begin != '"') {
          return false;
        }
        c = std::find(parameter_value_begin + 1, value.end(), '"');
        if (c == value.end()) {
          return false;
        }
        ++c;
        parameters_end = std::find(c, value.end(), ',');
        StringPiece::const_iterator v_begin = parameter_value_begin + 1;
        while (v_begin < c) {
          StringPiece::const_iterator v_end = v_begin;
          while (v_end < c - 1 && *v_end != ',') {
            ++v_end;
          }
          uint16_t v;
          if (!ParsePositiveInteger16(v_begin, v_end, &v)) {
            return false;
          }
          version.push_back(v);
          v_begin = v_end + 1;
          if (v_begin == c - 1) {
            // List ends in comma.
            return false;
          }
        }
      }
    }
    altsvc_vector->emplace_back(protocol_id, host, port, max_age, version);
    for (; c != value.end() && (*c == ' ' || *c == '\t' || *c == ','); ++c) {
    }
  }
  return true;
}

// static
std::string SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
    const AlternativeServiceVector& altsvc_vector) {
  if (altsvc_vector.empty()) {
    return std::string("clear");
  }
  const char kNibbleToHex[] = "0123456789ABCDEF";
  std::string value;
  for (const AlternativeService& altsvc : altsvc_vector) {
    if (!value.empty()) {
      value.push_back(',');
    }
    // Percent escape protocol id according to
    // http://tools.ietf.org/html/rfc7230#section-3.2.6.
    for (char c : altsvc.protocol_id) {
      if (isalnum(c)) {
        value.push_back(c);
        continue;
      }
      switch (c) {
        case '!':
        case '#':
        case '$':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
          value.push_back(c);
          break;
        default:
          value.push_back('%');
          // Network byte order is big-endian.
          value.push_back(kNibbleToHex[c >> 4]);
          value.push_back(kNibbleToHex[c & 0x0f]);
          break;
      }
    }
    value.push_back('=');
    value.push_back('"');
    for (char c : altsvc.host) {
      if (c == '"' || c == '\\') {
        value.push_back('\\');
      }
      value.push_back(c);
    }
    base::StringAppendF(&value, ":%d\"", altsvc.port);
    if (altsvc.max_age != 86400) {
      base::StringAppendF(&value, "; ma=%d", altsvc.max_age);
    }
    if (!altsvc.version.empty()) {
      value.append("; v=\"");
      for (VersionVector::const_iterator it = altsvc.version.begin();
           it != altsvc.version.end(); ++it) {
        if (it != altsvc.version.begin()) {
          value.append(",");
        }
        base::StringAppendF(&value, "%d", *it);
      }
      value.append("\"");
    }
  }
  return value;
}

// static
void SpdyAltSvcWireFormat::SkipWhiteSpace(StringPiece::const_iterator* c,
                                          StringPiece::const_iterator end) {
  for (; *c != end && (**c == ' ' || **c == '\t'); ++*c) {
  }
}

// static
bool SpdyAltSvcWireFormat::PercentDecode(StringPiece::const_iterator c,
                                         StringPiece::const_iterator end,
                                         std::string* output) {
  output->clear();
  for (; c != end; ++c) {
    if (*c != '%') {
      output->push_back(*c);
      continue;
    }
    DCHECK_EQ('%', *c);
    ++c;
    if (c == end || !isxdigit(*c)) {
      return false;
    }
    char decoded = tolower(*c);
    // '0' is 0, 'a' is 10.
    decoded += isdigit(*c) ? (0 - '0') : (10 - 'a');
    // Network byte order is big-endian.
    decoded <<= 4;
    ++c;
    if (c == end || !isxdigit(*c)) {
      return false;
    }
    decoded += tolower(*c);
    // '0' is 0, 'a' is 10.
    decoded += isdigit(*c) ? (0 - '0') : (10 - 'a');
    output->push_back(decoded);
  }
  return true;
}

// static
bool SpdyAltSvcWireFormat::ParseAltAuthority(StringPiece::const_iterator c,
                                             StringPiece::const_iterator end,
                                             std::string* host,
                                             uint16_t* port) {
  host->clear();
  for (; c != end && *c != ':'; ++c) {
    if (*c == '"') {
      // Port is mandatory.
      return false;
    }
    if (*c == '\\') {
      ++c;
      if (c == end) {
        return false;
      }
    }
    host->push_back(*c);
  }
  if (c == end) {
    return false;
  }
  DCHECK_EQ(':', *c);
  ++c;
  return ParsePositiveInteger16(c, end, port);
}

// static
bool SpdyAltSvcWireFormat::ParsePositiveInteger16(
    StringPiece::const_iterator c,
    StringPiece::const_iterator end,
    uint16_t* value) {
  return ParsePositiveIntegerImpl<uint16_t>(c, end, value);
}

// static
bool SpdyAltSvcWireFormat::ParsePositiveInteger32(
    StringPiece::const_iterator c,
    StringPiece::const_iterator end,
    uint32_t* value) {
  return ParsePositiveIntegerImpl<uint32_t>(c, end, value);
}

}  // namespace net
