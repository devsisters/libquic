// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/heap_profiler_allocation_context_tracker.h"

#include <algorithm>
#include <iterator>

#include "base/atomicops.h"
#include "base/threading/thread_local_storage.h"
#include "base/trace_event/heap_profiler_allocation_context.h"

namespace base {
namespace trace_event {

subtle::Atomic32 AllocationContextTracker::capture_enabled_ = 0;

namespace {

const size_t kMaxStackDepth = 128u;
const size_t kMaxTaskDepth = 16u;
AllocationContextTracker* const kInitializingSentinel =
    reinterpret_cast<AllocationContextTracker*>(-1);
const char kTracingOverhead[] = "tracing_overhead";

ThreadLocalStorage::StaticSlot g_tls_alloc_ctx_tracker = TLS_INITIALIZER;

// This function is added to the TLS slot to clean up the instance when the
// thread exits.
void DestructAllocationContextTracker(void* alloc_ctx_tracker) {
  delete static_cast<AllocationContextTracker*>(alloc_ctx_tracker);
}

}  // namespace

// static
AllocationContextTracker*
AllocationContextTracker::GetInstanceForCurrentThread() {
  AllocationContextTracker* tracker =
      static_cast<AllocationContextTracker*>(g_tls_alloc_ctx_tracker.Get());
  if (tracker == kInitializingSentinel)
    return nullptr;  // Re-entrancy case.

  if (!tracker) {
    g_tls_alloc_ctx_tracker.Set(kInitializingSentinel);
    tracker = new AllocationContextTracker();
    g_tls_alloc_ctx_tracker.Set(tracker);
  }

  return tracker;
}

AllocationContextTracker::AllocationContextTracker()
    : thread_name_(nullptr), ignore_scope_depth_(0) {
  pseudo_stack_.reserve(kMaxStackDepth);
  task_contexts_.reserve(kMaxTaskDepth);
}
AllocationContextTracker::~AllocationContextTracker() {}

// static
void AllocationContextTracker::SetCurrentThreadName(const char* name) {
  if (name && capture_enabled()) {
    GetInstanceForCurrentThread()->thread_name_ = name;
  }
}

// static
void AllocationContextTracker::SetCaptureEnabled(bool enabled) {
  // When enabling capturing, also initialize the TLS slot. This does not create
  // a TLS instance yet.
  if (enabled && !g_tls_alloc_ctx_tracker.initialized())
    g_tls_alloc_ctx_tracker.Initialize(DestructAllocationContextTracker);

  // Release ordering ensures that when a thread observes |capture_enabled_| to
  // be true through an acquire load, the TLS slot has been initialized.
  subtle::Release_Store(&capture_enabled_, enabled);
}

void AllocationContextTracker::PushPseudoStackFrame(
    const char* trace_event_name) {
  // Impose a limit on the height to verify that every push is popped, because
  // in practice the pseudo stack never grows higher than ~20 frames.
  if (pseudo_stack_.size() < kMaxStackDepth)
    pseudo_stack_.push_back(trace_event_name);
  else
    NOTREACHED();
}

void AllocationContextTracker::PopPseudoStackFrame(
    const char* trace_event_name) {
  // Guard for stack underflow. If tracing was started with a TRACE_EVENT in
  // scope, the frame was never pushed, so it is possible that pop is called
  // on an empty stack.
  if (pseudo_stack_.empty())
    return;

  // Assert that pushes and pops are nested correctly. This DCHECK can be
  // hit if some TRACE_EVENT macro is unbalanced (a TRACE_EVENT_END* call
  // without a corresponding TRACE_EVENT_BEGIN).
  DCHECK_EQ(trace_event_name, pseudo_stack_.back())
      << "Encountered an unmatched TRACE_EVENT_END";

  pseudo_stack_.pop_back();
}

void AllocationContextTracker::PushCurrentTaskContext(const char* context) {
  DCHECK(context);
  if (task_contexts_.size() < kMaxTaskDepth)
    task_contexts_.push_back(context);
  else
    NOTREACHED();
}

void AllocationContextTracker::PopCurrentTaskContext(const char* context) {
  DCHECK_EQ(context, task_contexts_.back())
      << "Encountered an unmatched context end";
  task_contexts_.pop_back();
}

// static
AllocationContext AllocationContextTracker::GetContextSnapshot() {
  AllocationContext ctx;

  if (ignore_scope_depth_) {
    ctx.backtrace.frames[0] = StackFrame::FromTraceEventName(kTracingOverhead);
    ctx.type_name = kTracingOverhead;
    ctx.backtrace.frame_count = 1;
    return ctx;
  }

  // Fill the backtrace.
  {
    auto backtrace = std::begin(ctx.backtrace.frames);
    auto backtrace_end = std::end(ctx.backtrace.frames);

    // Add the thread name as the first entry
    if (thread_name_) {
      *backtrace++ = StackFrame::FromThreadName(thread_name_);
    }

    for (const char* event_name: pseudo_stack_) {
      if (backtrace == backtrace_end) {
        break;
      }
      *backtrace++ = StackFrame::FromTraceEventName(event_name);
    }

    ctx.backtrace.frame_count = backtrace - std::begin(ctx.backtrace.frames);
  }

  // TODO(ssid): Fix crbug.com/594803 to add file name as 3rd dimension
  // (component name) in the heap profiler and not piggy back on the type name.
  ctx.type_name = task_contexts_.empty() ? nullptr : task_contexts_.back();

  return ctx;
}

}  // namespace trace_event
}  // namespace base
