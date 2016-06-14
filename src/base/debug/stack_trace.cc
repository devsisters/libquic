// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/stack_trace.h"

#include <string.h>

#include <algorithm>
#include <sstream>

#include "base/macros.h"

#if HAVE_TRACE_STACK_FRAME_POINTERS && defined(OS_ANDROID)
#include <pthread.h>
#include "base/process/process_handle.h"
#include "base/threading/platform_thread.h"
#endif

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

#if defined(OS_ANDROID)

static uintptr_t GetStackEnd() {
  // Bionic reads proc/maps on every call to pthread_getattr_np() when called
  // from the main thread. So we need to cache end of stack in that case to get
  // acceptable performance.
  // For all other threads pthread_getattr_np() is fast enough as it just reads
  // values from its pthread_t argument.
  static uintptr_t main_stack_end = 0;

  bool is_main_thread = GetCurrentProcId() == PlatformThread::CurrentId();

  if (is_main_thread && main_stack_end) {
    return main_stack_end;
  }

  uintptr_t stack_begin = 0;
  size_t stack_size = 0;
  pthread_attr_t attributes;
  int error = pthread_getattr_np(pthread_self(), &attributes);
  if (!error) {
    error = pthread_attr_getstack(
        &attributes,
        reinterpret_cast<void**>(&stack_begin),
        &stack_size);
    pthread_attr_destroy(&attributes);
  }
  DCHECK(!error);

  uintptr_t stack_end = stack_begin + stack_size;
  if (is_main_thread) {
    main_stack_end = stack_end;
  }
  return stack_end;
}

#endif  // defined(OS_ANDROID)

size_t TraceStackFramePointers(const void** out_trace,
                               size_t max_depth,
                               size_t skip_initial) {
  // Usage of __builtin_frame_address() enables frame pointers in this
  // function even if they are not enabled globally. So 'sp' will always
  // be valid.
  uintptr_t sp = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));

#if defined(OS_ANDROID)
  uintptr_t stack_end = GetStackEnd();
#endif

  size_t depth = 0;
  while (depth < max_depth) {
#if defined(__arm__) && defined(__GNUC__) && !defined(__clang__)
    // GCC and LLVM generate slightly different frames on ARM, see
    // https://llvm.org/bugs/show_bug.cgi?id=18505 - LLVM generates
    // x86-compatible frame, while GCC needs adjustment.
    sp -= sizeof(uintptr_t);
#endif

#if defined(OS_ANDROID)
    // Both sp[0] and s[1] must be valid.
    if (sp + 2 * sizeof(uintptr_t) > stack_end) {
      break;
    }
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
