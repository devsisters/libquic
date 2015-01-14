// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_entry.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "net/spdy/hpack_string_util.h"

namespace net {

using base::StringPiece;

const size_t HpackEntry::kSizeOverhead = 32;

HpackEntry::HpackEntry(StringPiece name,
                       StringPiece value,
                       bool is_static,
                       size_t insertion_index)
    : name_(name.data(), name.size()),
      value_(value.data(), value.size()),
      insertion_index_(insertion_index),
      type_(is_static ? STATIC : DYNAMIC) {
}

HpackEntry::HpackEntry(StringPiece name, StringPiece value)
    : name_(name.data(), name.size()),
      value_(value.data(), value.size()),
      insertion_index_(0),
      type_(LOOKUP) {
}

HpackEntry::HpackEntry()
    : insertion_index_(0),
      type_(LOOKUP) {
}

HpackEntry::~HpackEntry() {}

// static
size_t HpackEntry::Size(StringPiece name, StringPiece value) {
  return name.size() + value.size() + kSizeOverhead;
}
size_t HpackEntry::Size() const {
  return Size(name(), value());
}

std::string HpackEntry::GetDebugString() const {
  return "{ name: \"" + name_ +
      "\", value: \"" + value_ +
      "\", " + (IsStatic() ? "static" : "dynamic") + " }";
}

}  // namespace net
