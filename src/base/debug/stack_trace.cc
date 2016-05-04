// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/stack_trace.h"

#include <string.h>

#include <algorithm>
#include <sstream>

#include "base/macros.h"

namespace base {
namespace debug {

StackTrace::StackTrace() { }

StackTrace::StackTrace(const void* const* trace, size_t count) {
  count = std::min(count, arraysize(trace_));
  if (count)
    memcpy(trace_, trace, count * sizeof(trace_[0]));
  count_ = count;
}

StackTrace::~StackTrace() {
}

void StackTrace::OutputToStream(std::ostream* os) const { }

const void *const *StackTrace::Addresses(size_t* count) const {
  *count = count_;
  if (count_)
    return trace_;
  return NULL;
}

std::string StackTrace::ToString() const {
  std::stringstream stream;
#if 0
#if !defined(__UCLIBC__)
  OutputToStream(&stream);
#endif
#endif
  return stream.str();
}

#if HAVE_TRACE_STACK_FRAME_POINTERS

size_t TraceStackFramePointers(const void** out_trace,
                               size_t max_depth,
                               size_t skip_initial) {
  // Usage of __builtin_frame_address() enables frame pointers in this
  // function even if they are not enabled globally. So 'sp' will always
  // be valid.
  uintptr_t sp = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));

  size_t depth = 0;
  while (depth < max_depth) {
#if defined(__arm__) && defined(__GNUC__) && !defined(__clang__)
    // GCC and LLVM generate slightly different frames on ARM, see
    // https://llvm.org/bugs/show_bug.cgi?id=18505 - LLVM generates
    // x86-compatible frame, while GCC needs adjustment.
    sp -= sizeof(uintptr_t);
#endif

    if (skip_initial != 0) {
      skip_initial--;
    } else {
      out_trace[depth++] = reinterpret_cast<const void**>(sp)[1];
    }

    // Find out next frame pointer
    // (heuristics are from TCMalloc's stacktrace functions)
    {
      uintptr_t next_sp = reinterpret_cast<const uintptr_t*>(sp)[0];

      // With the stack growing downwards, older stack frame must be
      // at a greater address that the current one.
      if (next_sp <= sp) break;

      // Assume stack frames larger than 100,000 bytes are bogus.
      if (next_sp - sp > 100000) break;

      // Check alignment.
      if (sp & (sizeof(void*) - 1)) break;

      sp = next_sp;
    }
  }

  return depth;
}

#endif  // HAVE_TRACE_STACK_FRAME_POINTERS

}  // namespace debug
}  // namespace base
