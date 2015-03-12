// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/source_address_token.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"

using std::string;

namespace net {

SourceAddressToken::SourceAddressToken()
    : timestamp_(0), has_cached_network_parameters_(false) {
}

SourceAddressToken::~SourceAddressToken() {
}

string SourceAddressToken::SerializeAsString() const {
  string out;
  out.push_back(static_cast<char>(ip_.size()));
  out.append(ip_);
  string time_str = base::Int64ToString(timestamp_);
  out.push_back(static_cast<char>(time_str.size()));
  out.append(time_str);
  // TODO(rtenneti): Implement serialization of optional CachedNetworkParameters
  // when they are used.
  return out;
}

bool SourceAddressToken::ParseFromArray(const char* plaintext,
                                        size_t plaintext_length) {
  if (plaintext_length == 0) {
    return false;
  }
  size_t ip_len = plaintext[0];
  if (plaintext_length <= 1 + ip_len) {
    return false;
  }
  size_t time_len = plaintext[1 + ip_len];
  if (plaintext_length != 1 + ip_len + 1 + time_len) {
    return false;
  }

  string time_str(&plaintext[1 + ip_len + 1], time_len);
  int64 timestamp;
  if (!base::StringToInt64(time_str, &timestamp)) {
    return false;
  }

  ip_.assign(&plaintext[1], ip_len);
  timestamp_ = timestamp;

  // TODO(rtenneti): Implement parsing of optional CachedNetworkParameters when
  // they are used.
  return true;
}

SourceAddressTokens::SourceAddressTokens() {
}

SourceAddressTokens::~SourceAddressTokens() {
  STLDeleteElements(&tokens_);
}

string SourceAddressTokens::SerializeAsString() const {
  string out;

  for (size_t i = 0; i < tokens_size(); i++) {
    const SourceAddressToken& source_address_token = tokens(i);
    out.append(source_address_token.SerializeAsString());
  }
  return out;
}

bool SourceAddressTokens::ParseFromArray(const char* plaintext,
                                         size_t plaintext_length) {
  // TODO(rtenneti): Implement parsing of SourceAddressTokens when they are
  // used.
  return true;
}

}  // namespace net
