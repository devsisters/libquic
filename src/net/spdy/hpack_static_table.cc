// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack_static_table.h"

#include "base/logging.h"
#include "net/spdy/hpack_constants.h"
#include "net/spdy/hpack_entry.h"

namespace net {

HpackStaticTable::HpackStaticTable() {}

HpackStaticTable::~HpackStaticTable() {}

void HpackStaticTable::Initialize(const HpackStaticEntry* static_entry_table,
                                  size_t static_entry_count) {
  CHECK(!IsInitialized());

  int total_insertions = 0;
  for (const HpackStaticEntry* it = static_entry_table;
       it != static_entry_table + static_entry_count; ++it) {
    static_entries_.push_back(HpackEntry(StringPiece(it->name, it->name_len),
                                         StringPiece(it->value, it->value_len),
                                         true,  // is_static
                                         total_insertions));
    CHECK(static_index_.insert(&static_entries_.back()).second);

    ++total_insertions;
  }
}

bool HpackStaticTable::IsInitialized() const {
  return !static_entries_.empty();
}

}  // namespace net
