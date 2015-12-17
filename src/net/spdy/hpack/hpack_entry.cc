// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_entry.h"

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"

namespace net {

using base::StringPiece;

const size_t HpackEntry::kSizeOverhead = 32;

HpackEntry::HpackEntry(StringPiece name,
                       StringPiece value,
                       bool is_static,
                       size_t insertion_index)
    : name_(name.data(), name.size()),
      value_(value.data(), value.size()),
      name_ref_(name_),
      value_ref_(value_),
      insertion_index_(insertion_index),
      type_(is_static ? STATIC : DYNAMIC) {}

HpackEntry::HpackEntry(StringPiece name, StringPiece value)
    : name_ref_(name), value_ref_(value), insertion_index_(0), type_(LOOKUP) {}

HpackEntry::HpackEntry() : insertion_index_(0), type_(LOOKUP) {}

HpackEntry::HpackEntry(const HpackEntry& other)
    : insertion_index_(other.insertion_index_), type_(other.type_) {
  if (type_ == LOOKUP) {
    name_ref_ = other.name_ref_;
    value_ref_ = other.value_ref_;
  } else {
    name_ = other.name_;
    value_ = other.value_;
    name_ref_.set(name_.data(), name_.size());
    value_ref_.set(value_.data(), value_.size());
  }
}

HpackEntry& HpackEntry::operator=(const HpackEntry& other) {
  insertion_index_ = other.insertion_index_;
  type_ = other.type_;
  if (type_ == LOOKUP) {
    name_ref_ = other.name_ref_;
    value_ref_ = other.value_ref_;
    return *this;
  }
  name_ = other.name_;
  value_ = other.value_;
  name_ref_.set(name_.data(), name_.size());
  value_ref_.set(value_.data(), value_.size());
  return *this;
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
  return "{ name: \"" + name_ref_.as_string() + "\", value: \"" +
         value_ref_.as_string() + "\", index: " +
         base::SizeTToString(insertion_index_) +
         (IsStatic() ? " static" : (IsLookup() ? " lookup" : " dynamic")) +
         " }";
}

}  // namespace net
