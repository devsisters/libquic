// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_HEADER_TABLE_H_
#define NET_SPDY_HPACK_HEADER_TABLE_H_

#include <cstddef>
#include <deque>
#include <set>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/spdy/hpack/hpack_entry.h"

// All section references below are to http://tools.ietf.org/html/rfc7541.

namespace net {

namespace test {
class HpackHeaderTablePeer;
}  // namespace test

// A data structure for the static table (2.3.1) and the dynamic table (2.3.2).
class NET_EXPORT_PRIVATE HpackHeaderTable {
 public:
  friend class test::HpackHeaderTablePeer;

  // HpackHeaderTable takes advantage of the deque property that references
  // remain valid, so long as insertions & deletions are at the head & tail.
  // If this changes (eg we start to drop entries from the middle of the table),
  // this needs to be a std::list, in which case |*_index_| can be trivially
  // extended to map to list iterators.
  typedef std::deque<HpackEntry> EntryTable;

  // Implements a total ordering of HpackEntry on name(), value(), then index
  // ascending. Note that index may change over the lifetime of an HpackEntry,
  // but the relative index order of two entries will not. This comparator is
  // composed with the 'lookup' HpackEntry constructor to allow for efficient
  // lower-bounding of matching entries.
  struct NET_EXPORT_PRIVATE EntryComparator {
    bool operator()(const HpackEntry* lhs, const HpackEntry* rhs) const;
  };
  typedef std::set<HpackEntry*, EntryComparator> OrderedEntrySet;

  HpackHeaderTable();

  ~HpackHeaderTable();

  // Last-acknowledged value of SETTINGS_HEADER_TABLE_SIZE.
  size_t settings_size_bound() const { return settings_size_bound_; }

  // Current and maximum estimated byte size of the table, as described in
  // 4.1. Notably, this is /not/ the number of entries in the table.
  size_t size() const { return size_; }
  size_t max_size() const { return max_size_; }

  // Returns the entry matching the index, or NULL.
  const HpackEntry* GetByIndex(size_t index);

  // Returns the lowest-value entry having |name|, or NULL.
  const HpackEntry* GetByName(base::StringPiece name);

  // Returns the lowest-index matching entry, or NULL.
  const HpackEntry* GetByNameAndValue(base::StringPiece name,
                                      base::StringPiece value);

  // Returns the index of an entry within this header table.
  size_t IndexOf(const HpackEntry* entry) const;

  // Sets the maximum size of the header table, evicting entries if
  // necessary as described in 5.2.
  void SetMaxSize(size_t max_size);

  // Sets the SETTINGS_HEADER_TABLE_SIZE bound of the table. Will call
  // SetMaxSize() as needed to preserve max_size() <= settings_size_bound().
  void SetSettingsHeaderTableSize(size_t settings_size);

  // Determine the set of entries which would be evicted by the insertion
  // of |name| & |value| into the table, as per section 4.4. No eviction
  // actually occurs. The set is returned via range [begin_out, end_out).
  void EvictionSet(base::StringPiece name,
                   base::StringPiece value,
                   EntryTable::iterator* begin_out,
                   EntryTable::iterator* end_out);

  // Adds an entry for the representation, evicting entries as needed. |name|
  // and |value| must not be owned by an entry which could be evicted. The
  // added HpackEntry is returned, or NULL is returned if all entries were
  // evicted and the empty table is of insufficent size for the representation.
  const HpackEntry* TryAddEntry(base::StringPiece name,
                                base::StringPiece value);

  void DebugLogTableState() const;

 private:
  // Returns number of evictions required to enter |name| & |value|.
  size_t EvictionCountForEntry(base::StringPiece name,
                               base::StringPiece value) const;

  // Returns number of evictions required to reclaim |reclaim_size| table size.
  size_t EvictionCountToReclaim(size_t reclaim_size) const;

  // Evicts |count| oldest entries from the table.
  void Evict(size_t count);

  // |static_entries_| and |static_index_| are owned by HpackStaticTable
  // singleton.
  const EntryTable& static_entries_;
  EntryTable dynamic_entries_;

  const OrderedEntrySet& static_index_;
  OrderedEntrySet dynamic_index_;

  // Last acknowledged value for SETTINGS_HEADER_TABLE_SIZE.
  size_t settings_size_bound_;

  // Estimated current and maximum byte size of the table.
  // |max_size_| <= |settings_size_bound_|
  size_t size_;
  size_t max_size_;

  // Total number of table insertions which have occurred. Referenced by
  // IndexOf() for determination of an HpackEntry's table index.
  size_t total_insertions_;

  DISALLOW_COPY_AND_ASSIGN(HpackHeaderTable);
};

}  // namespace net

#endif  // NET_SPDY_HPACK_HEADER_TABLE_H_
