// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_alt_svc_wire_format.h"

#include <limits>
#include <string>

#include "base/logging.h"
#include "base/strings/stringprintf.h"

namespace net {

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

// static
bool SpdyAltSvcWireFormat::ParseHeaderFieldValue(
    StringPiece value,
    AlternativeServiceVector* altsvc_vector) {
  altsvc_vector->clear();
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
    uint16 port;
    if (!ParseAltAuthority(alt_authority_begin, c, &host, &port)) {
      return false;
    }
    ++c;
    // Parse parameters.
    uint32 max_age = 86400;
    double p = 1.0;
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
      } else if (parameter_name.compare("p") == 0) {
        if (!ParseProbability(parameter_value_begin, c, &p)) {
          return false;
        }
      }
    }
    altsvc_vector->push_back(
        AlternativeService(protocol_id, host, port, max_age, p));
    for (; c != value.end() && (*c == ' ' || *c == '\t' || *c == ','); ++c) {
    }
  }
  return true;
}

// static
std::string SpdyAltSvcWireFormat::SerializeHeaderFieldValue(
    const AlternativeServiceVector& altsvc_vector) {
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
    if (altsvc.p != 1.0) {
      base::StringAppendF(&value, "; p=%.2f", altsvc.p);
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
                                             uint16* port) {
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
    uint16* value) {
  return ParsePositiveIntegerImpl<uint16>(c, end, value);
}

// static
bool SpdyAltSvcWireFormat::ParsePositiveInteger32(
    StringPiece::const_iterator c,
    StringPiece::const_iterator end,
    uint32* value) {
  return ParsePositiveIntegerImpl<uint32>(c, end, value);
}

// Probability is a decimal fraction between 0.0 and 1.0, inclusive, with
// optional leading zero, optional decimal point, and optional digits following
// the decimal point, with the restriction that there has to be at least one
// digit (that is, "" and "." are not valid).
// static
bool SpdyAltSvcWireFormat::ParseProbability(StringPiece::const_iterator c,
                                            StringPiece::const_iterator end,
                                            double* p) {
  // "" is invalid.
  if (c == end) {
    return false;
  }
  // "." is invalid.
  if (end - c == 1 && *c == '.') {
    return false;
  }
  if (*c == '1') {
    *p = 1.0;
    ++c;
  } else {
    *p = 0.0;
    if (*c == '0') {
      ++c;
    }
  }
  if (c == end) {
    return true;
  }
  if (*c != '.') {
    return false;
  }
  // So far we could have had ".", "0.", or "1.".
  ++c;
  double place_value = 0.1;
  for (; c != end && isdigit(*c); ++c) {
    *p += place_value * (*c - '0');
    place_value *= 0.1;
  }
  return (c == end && *p <= 1.0);
}

}  // namespace net
