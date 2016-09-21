// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_block.h"

#include <string.h>

#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "base/macros.h"
#include "base/values.h"
#include "net/base/arena.h"
#include "net/http/http_log_util.h"

using base::StringPiece;
using std::dec;
using std::hex;
using std::max;
using std::min;
using std::string;

namespace net {
namespace {

// SpdyHeaderBlock::Storage allocates blocks of this size by default.
const size_t kDefaultStorageBlockSize = 2048;

const char kCookieKey[] = "cookie";

}  // namespace

// This class provides a backing store for StringPieces. It previously used
// custom allocation logic, but now uses an UnsafeArena instead. It has the
// property that StringPieces that refer to data in Storage are never
// invalidated until the Storage is deleted or Clear() is called.
//
// Write operations always append to the last block. If there is not enough
// space to perform the write, a new block is allocated, and any unused space
// is wasted.
class SpdyHeaderBlock::Storage {
 public:
  Storage() : arena_(kDefaultStorageBlockSize) {}
  ~Storage() { Clear(); }

  StringPiece Write(const StringPiece s) {
    return StringPiece(arena_.Memdup(s.data(), s.size()), s.size());
  }

  // Given value, a string already in the arena, perform a realloc and append
  // separator and more to the end of the value's new location. If value is the
  // most recently added string (via Write), then UnsafeArena will not copy the
  // existing value but instead will increase the space reserved for value.
  StringPiece Realloc(StringPiece value,
                      StringPiece separator,
                      StringPiece more) {
    size_t total_length = value.size() + separator.size() + more.size();
    char* ptr = const_cast<char*>(value.data());
    ptr = arena_.Realloc(ptr, value.size(), total_length);
    StringPiece result(ptr, total_length);
    ptr += value.size();
    memcpy(ptr, separator.data(), separator.size());
    ptr += separator.size();
    memcpy(ptr, more.data(), more.size());
    return result;
  }

  // If |s| points to the most recent allocation from arena_, the arena will
  // reclaim the memory. Otherwise, this method is a no-op.
  void Rewind(const StringPiece s) {
    arena_.Free(const_cast<char*>(s.data()), s.size());
  }

  void Clear() { arena_.Reset(); }

 private:
  UnsafeArena arena_;
};

SpdyHeaderBlock::StringPieceProxy::StringPieceProxy(
    SpdyHeaderBlock::MapType* block,
    SpdyHeaderBlock::Storage* storage,
    SpdyHeaderBlock::MapType::iterator lookup_result,
    const StringPiece key)
    : block_(block),
      storage_(storage),
      lookup_result_(lookup_result),
      key_(key),
      valid_(true) {}

SpdyHeaderBlock::StringPieceProxy::StringPieceProxy(StringPieceProxy&& other)
    : block_(other.block_),
      storage_(other.storage_),
      lookup_result_(other.lookup_result_),
      key_(other.key_),
      valid_(true) {
  other.valid_ = false;
}

SpdyHeaderBlock::StringPieceProxy& SpdyHeaderBlock::StringPieceProxy::operator=(
    SpdyHeaderBlock::StringPieceProxy&& other) {
  block_ = other.block_;
  storage_ = other.storage_;
  lookup_result_ = other.lookup_result_;
  key_ = other.key_;
  valid_ = true;
  other.valid_ = false;
  return *this;
}

SpdyHeaderBlock::StringPieceProxy::~StringPieceProxy() {
  // If the StringPieceProxy is destroyed while lookup_result_ == block_->end(),
  // the assignment operator was never used, and the block's Storage can
  // reclaim the memory used by the key. This makes lookup-only access to
  // SpdyHeaderBlock through operator[] memory-neutral.
  if (valid_ && lookup_result_ == block_->end()) {
    storage_->Rewind(key_);
  }
}

SpdyHeaderBlock::StringPieceProxy& SpdyHeaderBlock::StringPieceProxy::operator=(
    const StringPiece value) {
  if (lookup_result_ == block_->end()) {
    DVLOG(1) << "Inserting: (" << key_ << ", " << value << ")";
    lookup_result_ =
        block_->insert(std::make_pair(key_, storage_->Write(value))).first;
  } else {
    DVLOG(1) << "Updating key: " << key_ << " with value: " << value;
    lookup_result_->second = storage_->Write(value);
  }
  return *this;
}

SpdyHeaderBlock::StringPieceProxy::operator StringPiece() const {
  return (lookup_result_ == block_->end()) ? StringPiece()
                                           : lookup_result_->second;
}

SpdyHeaderBlock::SpdyHeaderBlock() {}

SpdyHeaderBlock::SpdyHeaderBlock(SpdyHeaderBlock&& other) {
  block_.swap(other.block_);
  storage_.swap(other.storage_);
}

SpdyHeaderBlock::~SpdyHeaderBlock() {}

SpdyHeaderBlock& SpdyHeaderBlock::operator=(SpdyHeaderBlock&& other) {
  block_.swap(other.block_);
  storage_.swap(other.storage_);
  return *this;
}

SpdyHeaderBlock SpdyHeaderBlock::Clone() const {
  SpdyHeaderBlock copy;
  for (auto iter : *this) {
    copy.AppendHeader(iter.first, iter.second);
  }
  return copy;
}

bool SpdyHeaderBlock::operator==(const SpdyHeaderBlock& other) const {
  return size() == other.size() && std::equal(begin(), end(), other.begin());
}

bool SpdyHeaderBlock::operator!=(const SpdyHeaderBlock& other) const {
  return !(operator==(other));
}

string SpdyHeaderBlock::DebugString() const {
  if (empty()) {
    return "{}";
  }
  string output = "\n{\n";
  for (auto it = begin(); it != end(); ++it) {
    output +=
        "  " + it->first.as_string() + ":" + it->second.as_string() + "\n";
  }
  output.append("}\n");
  return output;
}

void SpdyHeaderBlock::clear() {
  block_.clear();
  storage_.reset();
}

void SpdyHeaderBlock::insert(
    const SpdyHeaderBlock::MapType::value_type& value) {
  ReplaceOrAppendHeader(value.first, value.second);
}

SpdyHeaderBlock::StringPieceProxy SpdyHeaderBlock::operator[](
    const StringPiece key) {
  DVLOG(2) << "Operator[] saw key: " << key;
  StringPiece out_key;
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    // We write the key first, to assure that the StringPieceProxy has a
    // reference to a valid StringPiece in its operator=.
    out_key = GetStorage()->Write(key);
    DVLOG(2) << "Key written as: " << std::hex
             << static_cast<const void*>(key.data()) << ", " << std::dec
             << key.size();
  } else {
    out_key = iter->first;
  }
  return StringPieceProxy(&block_, GetStorage(), iter, out_key);
}

StringPiece SpdyHeaderBlock::GetHeader(const StringPiece key) const {
  auto iter = block_.find(key);
  return iter == block_.end() ? StringPiece() : iter->second;
}

void SpdyHeaderBlock::ReplaceOrAppendHeader(const StringPiece key,
                                            const StringPiece value) {
  // TODO(birenroy): Write new value in place of old value, if it fits.
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    DVLOG(1) << "Inserting: (" << key << ", " << value << ")";
    AppendHeader(key, value);
  } else {
    DVLOG(1) << "Updating key: " << iter->first << " with value: " << value;
    iter->second = GetStorage()->Write(value);
  }
}

void SpdyHeaderBlock::AppendValueOrAddHeader(const StringPiece key,
                                             const StringPiece value) {
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    DVLOG(1) << "Inserting: (" << key << ", " << value << ")";
    AppendHeader(key, value);
    return;
  }
  DVLOG(1) << "Updating key: " << iter->first << "; appending value: " << value;
  StringPiece separator("", 1);
  if (key == kCookieKey) {
    separator = "; ";
  }
  iter->second = GetStorage()->Realloc(iter->second, separator, value);
}

void SpdyHeaderBlock::AppendHeader(const StringPiece key,
                                   const StringPiece value) {
  block_.emplace(GetStorage()->Write(key), GetStorage()->Write(value));
}

SpdyHeaderBlock::Storage* SpdyHeaderBlock::GetStorage() {
  if (!storage_) {
    storage_.reset(new Storage);
  }
  return storage_.get();
}

#if 0
std::unique_ptr<base::Value> SpdyHeaderBlockNetLogCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::DictionaryValue* headers_dict = new base::DictionaryValue();
  for (SpdyHeaderBlock::const_iterator it = headers->begin();
       it != headers->end(); ++it) {
    headers_dict->SetWithoutPathExpansion(
        it->first.as_string(),
        new base::StringValue(ElideHeaderValueForNetLog(
            capture_mode, it->first.as_string(), it->second.as_string())));
  }
  dict->Set("headers", headers_dict);
  return std::move(dict);
}
#endif

bool SpdyHeaderBlockFromNetLogParam(
    const base::Value* event_param,
    SpdyHeaderBlock* headers) {
  headers->clear();

  const base::DictionaryValue* dict = NULL;
  const base::DictionaryValue* header_dict = NULL;

  if (!event_param ||
      !event_param->GetAsDictionary(&dict) ||
      !dict->GetDictionary("headers", &header_dict)) {
    return false;
  }

  for (base::DictionaryValue::Iterator it(*header_dict); !it.IsAtEnd();
       it.Advance()) {
    string value;
    if (!it.value().GetAsString(&value)) {
      headers->clear();
      return false;
    }
    (*headers)[it.key()] = value;
  }
  return true;
}

}  // namespace net
