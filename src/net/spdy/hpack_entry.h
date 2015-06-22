// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_HPACK_ENTRY_H_
#define NET_SPDY_HPACK_ENTRY_H_

#include <cstddef>
#include <set>
#include <string>

#include "base/basictypes.h"
#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace net {

// A structure for an entry in the static table (3.3.1)
// and the header table (3.3.2).
class NET_EXPORT_PRIVATE HpackEntry {
 public:
  // The constant amount added to name().size() and value().size() to
  // get the size of an HpackEntry as defined in 5.1.
  static const size_t kSizeOverhead;

  // Creates an entry. Preconditions:
  // - |is_static| captures whether this entry is a member of the static
  //   or dynamic header table.
  // - |insertion_index| is this entry's index in the total set of entries ever
  //   inserted into the header table (including static entries).
  //
  // The combination of |is_static| and |insertion_index| allows an
  // HpackEntryTable to determine the index of an HpackEntry in O(1) time.
  HpackEntry(base::StringPiece name,
             base::StringPiece value,
             bool is_static,
             size_t insertion_index);

  // Create a 'lookup' entry (only) suitable for querying a HpackEntrySet. The
  // instance InsertionIndex() always returns 0 and IsLookup() returns true.
  HpackEntry(base::StringPiece name, base::StringPiece value);

  // Creates an entry with empty name and value. Only defined so that
  // entries can be stored in STL containers.
  HpackEntry();

  ~HpackEntry();

  const std::string& name() const { return name_; }
  const std::string& value() const { return value_; }

  // Returns whether this entry is a member of the static (as opposed to
  // dynamic) table.
  bool IsStatic() const { return type_ == STATIC; }

  // Returns whether this entry is a lookup-only entry.
  bool IsLookup() const { return type_ == LOOKUP; }

  // Used to compute the entry's index in the header table.
  size_t InsertionIndex() const { return insertion_index_; }

  // Returns the size of an entry as defined in 5.1.
  static size_t Size(base::StringPiece name, base::StringPiece value);
  size_t Size() const;

  std::string GetDebugString() const;

 private:
  enum EntryType {
    LOOKUP,
    DYNAMIC,
    STATIC,
  };

  // TODO(jgraettinger): Reduce copies, possibly via SpdyPinnableBufferPiece.
  std::string name_;
  std::string value_;

  // The entry's index in the total set of entries ever inserted into the header
  // table.
  size_t insertion_index_;

  EntryType type_;
};

}  // namespace net

#endif  // NET_SPDY_HPACK_ENTRY_H_
