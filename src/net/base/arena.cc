// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/arena.h"

#include <string.h>

#include <algorithm>

#include "base/logging.h"

namespace net {

UnsafeArena::UnsafeArena(size_t block_size) : block_size_(block_size) {}

UnsafeArena::~UnsafeArena() {}

UnsafeArena::UnsafeArena(UnsafeArena&& other) = default;
UnsafeArena& UnsafeArena::operator=(UnsafeArena&& other) = default;

char* UnsafeArena::Memdup(const char* data, size_t size) {
  Reserve(size);
  Block& b = blocks_.back();
  DCHECK_GE(b.size, b.used + size);
  char* out = b.data.get() + b.used;
  b.used += size;
  memcpy(out, data, size);
  return out;
}

void UnsafeArena::Free(void* data, size_t size) {
  if (blocks_.empty()) {
    return;
  }
  Block& b = blocks_.back();
  if (size <= b.used &&
      reinterpret_cast<char*>(data) + size == b.data.get() + b.used) {
    // The memory region passed by the caller was the most recent allocation
    // from the final block in this arena.
    b.used -= size;
  }
}

void UnsafeArena::Reset() {
  blocks_.clear();
}

void UnsafeArena::Reserve(size_t additional_space) {
  if (blocks_.empty()) {
    AllocBlock(std::max(additional_space, block_size_));
  } else {
    const Block& last = blocks_.back();
    if (last.size < last.used + additional_space) {
      AllocBlock(std::max(additional_space, block_size_));
    }
  }
}

void UnsafeArena::AllocBlock(size_t size) {
  blocks_.push_back(Block(size));
}

UnsafeArena::Block::Block(size_t s) : data(new char[s]), size(s), used(0) {}

UnsafeArena::Block::~Block() {}

UnsafeArena::Block::Block(UnsafeArena::Block&& other)
    : size(other.size), used(other.used) {
  data = std::move(other.data);
}

UnsafeArena::Block& UnsafeArena::Block::operator=(UnsafeArena::Block&& other) {
  size = other.size;
  used = other.used;
  data = std::move(other.data);
  return *this;
}

}  // namespace net
