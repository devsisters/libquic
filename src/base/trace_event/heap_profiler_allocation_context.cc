// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_allocation_context.h"

#include <cstring>

#include "base/hash.h"
#include "base/macros.h"

namespace base {
namespace trace_event {

// Constructor that does not initialize members.
AllocationContext::AllocationContext() {}

// static
AllocationContext AllocationContext::Empty() {
  AllocationContext ctx;

  for (size_t i = 0; i < arraysize(ctx.backtrace.frames); i++)
    ctx.backtrace.frames[i] = nullptr;

  ctx.type_name = nullptr;

  return ctx;
}

bool operator==(const Backtrace& lhs, const Backtrace& rhs) {
  // Pointer equality of the stack frames is assumed, so instead of doing a deep
  // string comparison on all of the frames, a |memcmp| suffices.
  return std::memcmp(lhs.frames, rhs.frames, sizeof(lhs.frames)) == 0;
}

bool operator==(const AllocationContext& lhs, const AllocationContext& rhs) {
  return (lhs.backtrace == rhs.backtrace) && (lhs.type_name == rhs.type_name);
}

}  // namespace trace_event
}  // namespace base

namespace BASE_HASH_NAMESPACE {
using base::trace_event::AllocationContext;
using base::trace_event::Backtrace;

size_t hash<Backtrace>::operator()(const Backtrace& backtrace) const {
  return base::SuperFastHash(reinterpret_cast<const char*>(backtrace.frames),
                             sizeof(backtrace.frames));
}

size_t hash<AllocationContext>::operator()(const AllocationContext& ctx) const {
  size_t backtrace_hash = hash<Backtrace>()(ctx.backtrace);

  // Multiplicative hash from [Knuth 1998]. Works best if |size_t| is 32 bits,
  // because the magic number is a prime very close to 2^32 / golden ratio, but
  // will still redistribute keys bijectively on 64-bit architectures because
  // the magic number is coprime to 2^64.
  size_t type_hash = reinterpret_cast<size_t>(ctx.type_name) * 2654435761;

  // Multiply one side to break the commutativity of +. Multiplication with a
  // number coprime to |numeric_limits<size_t>::max() + 1| is bijective so
  // randomness is preserved.
  return (backtrace_hash * 3) + type_hash;
}

}  // BASE_HASH_NAMESPACE
