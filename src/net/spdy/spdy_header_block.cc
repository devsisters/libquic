// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_header_block.h"

#include <algorithm>
#include <ios>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/values.h"
#include "net/http/http_log_util.h"

using base::StringPiece;
using std::dec;
using std::hex;
using std::max;
using std::min;

namespace net {
namespace {

// SpdyHeaderBlock::Storage uses a small initial block in case we only have a
// minimal set of headers.
const size_t kInitialStorageBlockSize = 512;

// SpdyHeaderBlock::Storage allocates blocks of this size by default.
const size_t kDefaultStorageBlockSize = 2048;

// When copying a SpdyHeaderBlock, the new block will allocate at most this
// much memory for the initial contiguous block.
const size_t kMaxContiguousAllocation = 16 * 1024;

}  // namespace

// This class provides a backing store for StringPieces. It uses a sequence of
// large, contiguous blocks. It has the property that StringPieces that refer
// to data in Storage are never invalidated until the Storage is deleted.
//
// Write operations always append to the last block. If there is not enough
// space to perform the write, a new block is allocated, and any unused space
// is wasted.
class SpdyHeaderBlock::Storage {
 public:
  Storage() : bytes_used_(0) {}
  ~Storage() { Clear(); }

  void Reserve(size_t additional_space) {
    if (blocks_.empty()) {
      AllocBlock(max(additional_space, kInitialStorageBlockSize));
    } else {
      const Block& last = blocks_.back();
      if (last.size - last.used < additional_space) {
        AllocBlock(max(additional_space, kDefaultStorageBlockSize));
      }
    }
  }

  StringPiece Write(const StringPiece s) {
    Reserve(s.size());
    Block* last = &blocks_.back();
    memcpy(last->data + last->used, s.data(), s.size());
    StringPiece out(last->data + last->used, s.size());
    VLOG(3) << "Write result: " << hex
            << reinterpret_cast<const void*>(out.data()) << ", " << dec
            << out.size();
    last->used += s.size();
    bytes_used_ += s.size();
    return out;
  }

  void Clear() {
    while (!blocks_.empty()) {
      delete[] blocks_.back().data;
      blocks_.pop_back();
    }
    bytes_used_ = 0;
  }

  size_t BytesUsed() const { return bytes_used_; }

 private:
  // TODO(bnc): As soon as move semantics are allowed, change from naked pointer
  // to scoped_ptr<>, or better yet, unique_ptr<>.
  struct Block {
    char* data;
    size_t size = 0;
    size_t used = 0;

    Block(char* data, size_t s) : data(data), size(s), used(0) {}
  };

  void AllocBlock(size_t size) {
    blocks_.push_back(Block(new char[size], size));
  }

  std::vector<Block> blocks_;
  size_t bytes_used_;

  DISALLOW_COPY_AND_ASSIGN(Storage);
};

SpdyHeaderBlock::StringPieceProxy::StringPieceProxy(
    SpdyHeaderBlock::MapType* block,
    SpdyHeaderBlock::Storage* storage,
    SpdyHeaderBlock::MapType::iterator lookup_result,
    const StringPiece key)
    : block_(block),
      storage_(storage),
      lookup_result_(lookup_result),
      key_(key) {}

SpdyHeaderBlock::StringPieceProxy::~StringPieceProxy() {}

SpdyHeaderBlock::StringPieceProxy& SpdyHeaderBlock::StringPieceProxy::operator=(
    const StringPiece value) {
  if (lookup_result_ == block_->end()) {
    VLOG(1) << "Inserting: (" << key_ << ", " << value << ")";
    lookup_result_ =
        block_->insert(std::make_pair(key_, storage_->Write(value))).first;
  } else {
    VLOG(1) << "Updating key: " << key_ << " with value: " << value;
    lookup_result_->second = storage_->Write(value);
  }
  return *this;
}

SpdyHeaderBlock::StringPieceProxy::operator StringPiece() const {
  return (lookup_result_ == block_->end()) ? StringPiece()
                                           : lookup_result_->second;
}

void SpdyHeaderBlock::StringPieceProxy::reserve(size_t size) {
  storage_->Reserve(size);
}

SpdyHeaderBlock::SpdyHeaderBlock() : storage_(new Storage) {}

SpdyHeaderBlock::~SpdyHeaderBlock() {}

SpdyHeaderBlock::SpdyHeaderBlock(const SpdyHeaderBlock& other)
    : storage_(new Storage) {
  storage_->Reserve(min(other.storage_->BytesUsed(), kMaxContiguousAllocation));
  for (auto iter : other) {
    AppendHeader(iter.first, iter.second);
  }
}

SpdyHeaderBlock& SpdyHeaderBlock::operator=(const SpdyHeaderBlock& other) {
  clear();
  storage_->Reserve(min(other.storage_->BytesUsed(), kMaxContiguousAllocation));
  for (auto iter : other) {
    AppendHeader(iter.first, iter.second);
  }
  return *this;
}

bool SpdyHeaderBlock::operator==(const SpdyHeaderBlock& other) const {
  return std::equal(begin(), end(), other.begin());
}

bool SpdyHeaderBlock::operator!=(const SpdyHeaderBlock& other) const {
  return !(*this == other);
}

void SpdyHeaderBlock::clear() {
  block_.clear();
  storage_->Clear();
}

void SpdyHeaderBlock::insert(
    const SpdyHeaderBlock::MapType::value_type& value) {
  ReplaceOrAppendHeader(value.first, value.second);
}

SpdyHeaderBlock::StringPieceProxy SpdyHeaderBlock::operator[](
    const StringPiece key) {
  VLOG(2) << "Operator[] saw key: " << key;
  StringPiece out_key;
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    // We write the key first, to assure that the StringPieceProxy has a
    // reference to a valid StringPiece in its operator=.
    out_key = storage_->Write(key);
    VLOG(2) << "Key written as: " << hex << static_cast<const void*>(key.data())
            << ", " << dec << key.size();
  } else {
    out_key = iter->first;
  }
  return StringPieceProxy(&block_, storage_.get(), iter, out_key);
}

void SpdyHeaderBlock::ReplaceOrAppendHeader(const StringPiece key,
                                            const StringPiece value) {
  // TODO(birenroy): Write new value in place of old value, if it fits.
  auto iter = block_.find(key);
  if (iter == block_.end()) {
    VLOG(1) << "Inserting: (" << key << ", " << value << ")";
    AppendHeader(key, value);
  } else {
    VLOG(1) << "Updating key: " << iter->first << " with value: " << value;
    iter->second = storage_->Write(value);
  }
}

void SpdyHeaderBlock::AppendHeader(const StringPiece key,
                                   const StringPiece value) {
  block_.insert(make_pair(storage_->Write(key), storage_->Write(value)));
}

scoped_ptr<base::Value> SpdyHeaderBlockNetLogCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode) {
  scoped_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  base::DictionaryValue* headers_dict = new base::DictionaryValue();
  for (SpdyHeaderBlock::const_iterator it = headers->begin();
       it != headers->end(); ++it) {
    headers_dict->SetWithoutPathExpansion(
        it->first.as_string(),
        new base::StringValue(ElideHeaderValueForNetLog(
            capture_mode, it->first.as_string(), it->second.as_string())));
  }
  dict->Set("headers", headers_dict);
  return dict.Pass();
}

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
    std::string value;
    if (!it.value().GetAsString(&value)) {
      headers->clear();
      return false;
    }
    (*headers)[it.key()] = value;
  }
  return true;
}

}  // namespace net
