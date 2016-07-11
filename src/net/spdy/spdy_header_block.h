// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_HEADER_BLOCK_H_
#define NET_SPDY_SPDY_HEADER_BLOCK_H_

#include <stddef.h>

#include <map>
#include <memory>
#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/linked_hash_map.h"
#include "net/base/net_export.h"
#include "net/log/net_log.h"

namespace net {

// Allows arg-dependent lookup to work for logging's operator<<.
using ::operator<<;

namespace test {
class StringPieceProxyPeer;
}

// This class provides a key-value map that can be used to store SPDY header
// names and values. This data structure preserves insertion order.
//
// Under the hood, this data structure uses large, contiguous blocks of memory
// to store names and values. Lookups may be performed with StringPiece keys,
// and values are returned as StringPieces (via StringPieceProxy, below).
// Value StringPieces are valid as long as the SpdyHeaderBlock exists; allocated
// memory is never freed until SpdyHeaderBlock's destruction.
//
// This implementation does not make much of an effort to minimize wasted space.
// It's expected that keys are rarely deleted from a SpdyHeaderBlock.
class NET_EXPORT SpdyHeaderBlock {
 private:
  using MapType = linked_hash_map<base::StringPiece,
                                  base::StringPiece,
                                  base::StringPieceHash>;
  class Storage;

 public:
  using iterator = MapType::iterator;
  using const_iterator = MapType::const_iterator;
  using value_type = MapType::value_type;
  using reverse_iterator = MapType::reverse_iterator;

  class StringPieceProxy;

  SpdyHeaderBlock();
  SpdyHeaderBlock(const SpdyHeaderBlock& other) = delete;
  SpdyHeaderBlock(SpdyHeaderBlock&& other);
  ~SpdyHeaderBlock();

  SpdyHeaderBlock& operator=(const SpdyHeaderBlock& other) = delete;
  SpdyHeaderBlock& operator=(SpdyHeaderBlock&& other);
  SpdyHeaderBlock Clone() const;

  bool operator==(const SpdyHeaderBlock& other) const;
  bool operator!=(const SpdyHeaderBlock& other) const;

  // Provides a human readable multi-line representation of the stored header
  // keys and values.
  std::string DebugString() const;

  // These methods delegate to our MapType member.
  iterator begin() { return block_.begin(); }
  iterator end() { return block_.end(); }
  const_iterator begin() const { return block_.begin(); }
  const_iterator end() const { return block_.end(); }
  bool empty() const { return block_.empty(); }
  size_t size() const { return block_.size(); }
  iterator find(base::StringPiece key) { return block_.find(key); }
  const_iterator find(base::StringPiece key) const { return block_.find(key); }
  reverse_iterator rbegin() { return block_.rbegin(); }
  void erase(base::StringPiece key) { block_.erase(key); }

  // Clears both our MapType member and the memory used to hold headers.
  void clear();

  // These methods copy data into our backing storage.
  void insert(const MapType::value_type& value);
  void ReplaceOrAppendHeader(const base::StringPiece key,
                             const base::StringPiece value);

  // Allows either lookup or mutation of the value associated with a key.
  StringPieceProxy operator[](const base::StringPiece key);

  // Non-mutating lookup of header value. Returns empty StringPiece if key not
  // present. To distinguish between absence of header and empty header value,
  // use find().
  base::StringPiece GetHeader(const base::StringPiece key) const;

  // This object provides automatic conversions that allow SpdyHeaderBlock to be
  // nearly a drop-in replacement for linked_hash_map<string, string>. It reads
  // data from or writes data to a SpdyHeaderBlock::Storage.
  class NET_EXPORT StringPieceProxy {
   public:
    ~StringPieceProxy();

    // Moves are allowed.
    StringPieceProxy(StringPieceProxy&& other);
    StringPieceProxy& operator=(StringPieceProxy&& other);

    // Copies are not.
    StringPieceProxy(const StringPieceProxy& other) = delete;
    StringPieceProxy& operator=(const StringPieceProxy& other) = delete;

    // Assignment modifies the underlying SpdyHeaderBlock.
    StringPieceProxy& operator=(const base::StringPiece other);

    // Allows a StringPieceProxy to be automatically converted to a StringPiece.
    // This makes SpdyHeaderBlock::operator[] easy to use with StringPieces.
    operator base::StringPiece() const;

    std::string as_string() const {
      return static_cast<base::StringPiece>(*this).as_string();
    }

   private:
    friend class SpdyHeaderBlock;
    friend class test::StringPieceProxyPeer;

    StringPieceProxy(SpdyHeaderBlock::MapType* block,
                     SpdyHeaderBlock::Storage* storage,
                     SpdyHeaderBlock::MapType::iterator lookup_result,
                     const base::StringPiece key);

    SpdyHeaderBlock::MapType* block_;
    SpdyHeaderBlock::Storage* storage_;
    SpdyHeaderBlock::MapType::iterator lookup_result_;
    base::StringPiece key_;
    bool valid_;
  };

 private:
  void Write(const base::StringPiece s);
  void AppendHeader(const base::StringPiece key, const base::StringPiece value);

  MapType block_;
  std::unique_ptr<Storage> storage_;
};

// Converts a SpdyHeaderBlock into NetLog event parameters.
NET_EXPORT std::unique_ptr<base::Value> SpdyHeaderBlockNetLogCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode);

// Converts NetLog event parameters into a SPDY header block and writes them
// to |headers|.  |event_param| must have been created by
// SpdyHeaderBlockNetLogCallback.  On failure, returns false and clears
// |headers|.
NET_EXPORT bool SpdyHeaderBlockFromNetLogParam(
    const base::Value* event_param,
    SpdyHeaderBlock* headers);

}  // namespace net

#endif  // NET_SPDY_SPDY_HEADER_BLOCK_H_
