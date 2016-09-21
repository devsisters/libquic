// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_allocation_register.h"

#include <algorithm>

#include "base/trace_event/trace_event_memory_overhead.h"

namespace base {
namespace trace_event {

AllocationRegister::ConstIterator::ConstIterator(
    const AllocationRegister& alloc_register, AllocationIndex index)
    : register_(alloc_register),
      index_(index) {}

void AllocationRegister::ConstIterator::operator++() {
  index_ = register_.allocations_.Next(index_ + 1);
}

bool AllocationRegister::ConstIterator::operator!=(
    const ConstIterator& other) const {
  return index_ != other.index_;
}

AllocationRegister::Allocation
AllocationRegister::ConstIterator::operator*() const {
  return register_.GetAllocation(index_);
}

size_t AllocationRegister::BacktraceHasher::operator () (
    const Backtrace& backtrace) const {
  const size_t kSampleLength = 10;

  uintptr_t total_value = 0;

  size_t head_end = std::min(backtrace.frame_count, kSampleLength);
  for (size_t i = 0; i != head_end; ++i) {
    total_value += reinterpret_cast<uintptr_t>(backtrace.frames[i].value);
  }

  size_t tail_start = backtrace.frame_count -
      std::min(backtrace.frame_count - head_end, kSampleLength);
  for (size_t i = tail_start; i != backtrace.frame_count; ++i) {
    total_value += reinterpret_cast<uintptr_t>(backtrace.frames[i].value);
  }

  total_value += backtrace.frame_count;

  // These magic constants give best results in terms of average collisions
  // per backtrace. They were found by replaying real backtraces from Linux
  // and Android against different hash functions.
  return (total_value * 131101) >> 14;
}

size_t AllocationRegister::AddressHasher::operator () (
    const void* address) const {
  // The multiplicative hashing scheme from [Knuth 1998]. The value of |a| has
  // been chosen carefully based on measurements with real-word data (addresses
  // recorded from a Chrome trace run). It is the first prime after 2^17. For
  // |shift|, 13, 14 and 15 yield good results. These values are tuned to 2^18
  // buckets. Microbenchmarks show that this simple scheme outperforms fancy
  // hashes like Murmur3 by 20 to 40 percent.
  const uintptr_t key = reinterpret_cast<uintptr_t>(address);
  const uintptr_t a = 131101;
  const uintptr_t shift = 14;
  const uintptr_t h = (key * a) >> shift;
  return h;
}

AllocationRegister::AllocationRegister()
    : AllocationRegister(kAllocationCapacity, kBacktraceCapacity) {}

AllocationRegister::AllocationRegister(size_t allocation_capacity,
                                       size_t backtrace_capacity)
    : allocations_(allocation_capacity),
      backtraces_(backtrace_capacity) {}

AllocationRegister::~AllocationRegister() {
}

void AllocationRegister::Insert(const void* address,
                                size_t size,
                                const AllocationContext& context) {
  DCHECK(address != nullptr);
  if (size == 0) {
    return;
  }

  AllocationInfo info = {
      size,
      context.type_name,
      InsertBacktrace(context.backtrace)
  };

  // Try to insert the allocation.
  auto index_and_flag = allocations_.Insert(address, info);
  if (!index_and_flag.second) {
    // |address| is already there - overwrite the allocation info.
    auto& old_info = allocations_.Get(index_and_flag.first).second;
    RemoveBacktrace(old_info.backtrace_index);
    old_info = info;
  }
}

void AllocationRegister::Remove(const void* address) {
  auto index = allocations_.Find(address);
  if (index == AllocationMap::kInvalidKVIndex) {
    return;
  }

  const AllocationInfo& info = allocations_.Get(index).second;
  RemoveBacktrace(info.backtrace_index);
  allocations_.Remove(index);
}

bool AllocationRegister::Get(const void* address,
                             Allocation* out_allocation) const {
  auto index = allocations_.Find(address);
  if (index == AllocationMap::kInvalidKVIndex) {
    return false;
  }

  if (out_allocation) {
    *out_allocation = GetAllocation(index);
  }
  return true;
}

AllocationRegister::ConstIterator AllocationRegister::begin() const {
  return ConstIterator(*this, allocations_.Next(0));
}

AllocationRegister::ConstIterator AllocationRegister::end() const {
  return ConstIterator(*this, AllocationMap::kInvalidKVIndex);
}

void AllocationRegister::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) const {
  size_t allocated = sizeof(AllocationRegister);
  size_t resident = sizeof(AllocationRegister)
                    + allocations_.EstimateUsedMemory()
                    + backtraces_.EstimateUsedMemory();
  overhead->Add("AllocationRegister", allocated, resident);
}

AllocationRegister::BacktraceMap::KVIndex AllocationRegister::InsertBacktrace(
    const Backtrace& backtrace) {
  auto index = backtraces_.Insert(backtrace, 0).first;
  auto& backtrace_and_count = backtraces_.Get(index);
  backtrace_and_count.second++;
  return index;
}

void AllocationRegister::RemoveBacktrace(BacktraceMap::KVIndex index) {
  auto& backtrace_and_count = backtraces_.Get(index);
  if (--backtrace_and_count.second == 0) {
    // Backtrace is not referenced anymore - remove it.
    backtraces_.Remove(index);
  }
}

AllocationRegister::Allocation AllocationRegister::GetAllocation(
    AllocationMap::KVIndex index) const {
  const auto& address_and_info = allocations_.Get(index);
  const auto& backtrace_and_count = backtraces_.Get(
      address_and_info.second.backtrace_index);
  return {
      address_and_info.first,
      address_and_info.second.size,
      AllocationContext(
          backtrace_and_count.first,
          address_and_info.second.type_name)
  };
}

}  // namespace trace_event
}  // namespace base
