// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_SESSION_STATE_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_SESSION_STATE_H_

#include <memory>

#include "base/base_export.h"
#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"
#include "base/trace_event/trace_config.h"

namespace base {
namespace trace_event {

// Container for state variables that should be shared across all the memory
// dumps in a tracing session.
class BASE_EXPORT MemoryDumpSessionState
    : public RefCountedThreadSafe<MemoryDumpSessionState> {
 public:
  MemoryDumpSessionState();

  // Returns the stack frame deduplicator that should be used by memory dump
  // providers when doing a heap dump.
  StackFrameDeduplicator* stack_frame_deduplicator() const {
    return stack_frame_deduplicator_.get();
  }

  void SetStackFrameDeduplicator(
      std::unique_ptr<StackFrameDeduplicator> stack_frame_deduplicator);

  // Returns the type name deduplicator that should be used by memory dump
  // providers when doing a heap dump.
  TypeNameDeduplicator* type_name_deduplicator() const {
    return type_name_deduplicator_.get();
  }

  void SetTypeNameDeduplicator(
      std::unique_ptr<TypeNameDeduplicator> type_name_deduplicator);

  const TraceConfig::MemoryDumpConfig& memory_dump_config() const {
    return memory_dump_config_;
  }

  void SetMemoryDumpConfig(const TraceConfig::MemoryDumpConfig& config);

 private:
  friend class RefCountedThreadSafe<MemoryDumpSessionState>;
  ~MemoryDumpSessionState();

  // Deduplicates backtraces in heap dumps so they can be written once when the
  // trace is finalized.
  std::unique_ptr<StackFrameDeduplicator> stack_frame_deduplicator_;

  // Deduplicates type names in heap dumps so they can be written once when the
  // trace is finalized.
  std::unique_ptr<TypeNameDeduplicator> type_name_deduplicator_;

  // The memory dump config, copied at the time when the tracing session was
  // started.
  TraceConfig::MemoryDumpConfig memory_dump_config_;
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_SESSION_STATE_H_
