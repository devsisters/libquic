// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/hpack/hpack_header_table.h"

#include <algorithm>

#include "base/logging.h"
#include "net/spdy/hpack/hpack_constants.h"
#include "net/spdy/hpack/hpack_static_table.h"

namespace net {

using base::StringPiece;

bool HpackHeaderTable::EntryComparator::operator()(
    const HpackEntry* lhs,
    const HpackEntry* rhs) const {
  int result = lhs->name().compare(rhs->name());
  if (result != 0) {
    return result < 0;
  }
  result = lhs->value().compare(rhs->value());
  if (result != 0) {
    return result < 0;
  }
  const size_t lhs_index = lhs->IsLookup() ? 0 : 1 + lhs->InsertionIndex();
  const size_t rhs_index = rhs->IsLookup() ? 0 : 1 + rhs->InsertionIndex();
  DCHECK(lhs == rhs || lhs_index != rhs_index)
      << "lhs: (" << lhs->name() << ", " << rhs->value() << ") rhs: ("
      << rhs->name() << ", " << rhs->value() << ")"
      << " lhs index: " << lhs_index << " rhs index: " << rhs_index;
  return lhs_index < rhs_index;
}

HpackHeaderTable::HpackHeaderTable()
    : static_entries_(ObtainHpackStaticTable().GetStaticEntries()),
      static_index_(ObtainHpackStaticTable().GetStaticIndex()),
      settings_size_bound_(kDefaultHeaderTableSizeSetting),
      size_(0),
      max_size_(kDefaultHeaderTableSizeSetting),
      total_insertions_(static_entries_.size()) {}

HpackHeaderTable::~HpackHeaderTable() {}

const HpackEntry* HpackHeaderTable::GetByIndex(size_t index) {
  if (index == 0) {
    return NULL;
  }
  index -= 1;
  if (index < static_entries_.size()) {
    return &static_entries_[index];
  }
  index -= static_entries_.size();
  if (index < dynamic_entries_.size()) {
    return &dynamic_entries_[index];
  }
  return NULL;
}

const HpackEntry* HpackHeaderTable::GetByName(StringPiece name) {
  HpackEntry query(name, "");
  {
    OrderedEntrySet::const_iterator it = static_index_.lower_bound(&query);
    if (it != static_index_.end() && (*it)->name() == name) {
      return *it;
    }
  }
  {
    OrderedEntrySet::const_iterator it = dynamic_index_.lower_bound(&query);
    if (it != dynamic_index_.end() && (*it)->name() == name) {
      return *it;
    }
  }
  return NULL;
}

const HpackEntry* HpackHeaderTable::GetByNameAndValue(StringPiece name,
                                                      StringPiece value) {
  HpackEntry query(name, value);
  {
    OrderedEntrySet::const_iterator it = static_index_.lower_bound(&query);
    if (it != static_index_.end() && (*it)->name() == name &&
        (*it)->value() == value) {
      return *it;
    }
  }
  {
    OrderedEntrySet::const_iterator it = dynamic_index_.lower_bound(&query);
    if (it != dynamic_index_.end() && (*it)->name() == name &&
        (*it)->value() == value) {
      return *it;
    }
  }
  return NULL;
}

size_t HpackHeaderTable::IndexOf(const HpackEntry* entry) const {
  if (entry->IsLookup()) {
    return 0;
  } else if (entry->IsStatic()) {
    return 1 + entry->InsertionIndex();
  } else {
    return total_insertions_ - entry->InsertionIndex() + static_entries_.size();
  }
}

void HpackHeaderTable::SetMaxSize(size_t max_size) {
  CHECK_LE(max_size, settings_size_bound_);

  max_size_ = max_size;
  if (size_ > max_size_) {
    Evict(EvictionCountToReclaim(size_ - max_size_));
    CHECK_LE(size_, max_size_);
  }
}

void HpackHeaderTable::SetSettingsHeaderTableSize(size_t settings_size) {
  settings_size_bound_ = settings_size;
  if (settings_size_bound_ < max_size_) {
    SetMaxSize(settings_size_bound_);
  }
}

void HpackHeaderTable::EvictionSet(StringPiece name,
                                   StringPiece value,
                                   EntryTable::iterator* begin_out,
                                   EntryTable::iterator* end_out) {
  size_t eviction_count = EvictionCountForEntry(name, value);
  *begin_out = dynamic_entries_.end() - eviction_count;
  *end_out = dynamic_entries_.end();
}

size_t HpackHeaderTable::EvictionCountForEntry(StringPiece name,
                                               StringPiece value) const {
  size_t available_size = max_size_ - size_;
  size_t entry_size = HpackEntry::Size(name, value);

  if (entry_size <= available_size) {
    // No evictions are required.
    return 0;
  }
  return EvictionCountToReclaim(entry_size - available_size);
}

size_t HpackHeaderTable::EvictionCountToReclaim(size_t reclaim_size) const {
  size_t count = 0;
  for (EntryTable::const_reverse_iterator it = dynamic_entries_.rbegin();
       it != dynamic_entries_.rend() && reclaim_size != 0; ++it, ++count) {
    reclaim_size -= std::min(reclaim_size, it->Size());
  }
  return count;
}

void HpackHeaderTable::Evict(size_t count) {
  for (size_t i = 0; i != count; ++i) {
    CHECK(!dynamic_entries_.empty());
    HpackEntry* entry = &dynamic_entries_.back();

    size_ -= entry->Size();
    CHECK_EQ(1u, dynamic_index_.erase(entry));
    dynamic_entries_.pop_back();
  }
}

const HpackEntry* HpackHeaderTable::TryAddEntry(StringPiece name,
                                                StringPiece value) {
  Evict(EvictionCountForEntry(name, value));

  size_t entry_size = HpackEntry::Size(name, value);
  if (entry_size > (max_size_ - size_)) {
    // Entire table has been emptied, but there's still insufficient room.
    DCHECK(dynamic_entries_.empty());
    DCHECK_EQ(0u, size_);
    return NULL;
  }
  dynamic_entries_.push_front(HpackEntry(name, value,
                                         false,  // is_static
                                         total_insertions_));
  CHECK(dynamic_index_.insert(&dynamic_entries_.front()).second);

  size_ += entry_size;
  ++total_insertions_;

  return &dynamic_entries_.front();
}

void HpackHeaderTable::DebugLogTableState() const {
  DVLOG(2) << "Dynamic table:";
  for (EntryTable::const_iterator it = dynamic_entries_.begin();
       it != dynamic_entries_.end(); ++it) {
    DVLOG(2) << "  " << it->GetDebugString();
  }
  DVLOG(2) << "Full Static Index:";
  for (OrderedEntrySet::const_iterator it = static_index_.begin();
       it != static_index_.end(); ++it) {
    DVLOG(2) << "  " << (*it)->GetDebugString();
  }
  DVLOG(2) << "Full Dynamic Index:";
  for (OrderedEntrySet::const_iterator it = dynamic_index_.begin();
       it != dynamic_index_.end(); ++it) {
    DVLOG(2) << "  " << (*it)->GetDebugString();
  }
}

}  // namespace net
