// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/trace_log.h"

#include <algorithm>
#include <cmath>
#include <memory>
#include <utility>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/command_line.h"
#include "base/debug/leak_annotations.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted_memory.h"
#include "base/memory/singleton.h"
#include "base/process/process_metrics.h"
#include "base/stl_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_tokenizer.h"
#include "base/strings/stringprintf.h"
#include "base/sys_info.h"
#include "base/third_party/dynamic_annotations/dynamic_annotations.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_id_name_manager.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/threading/worker_pool.h"
#include "base/time/time.h"
#include "base/trace_event/heap_profiler.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_buffer.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_event_synthetic_delay.h"
#include "base/trace_event/trace_sampling_thread.h"
#include "build/build_config.h"

#if defined(OS_WIN)
#include "base/trace_event/trace_event_etw_export_win.h"
#endif

// The thread buckets for the sampling profiler.
BASE_EXPORT TRACE_EVENT_API_ATOMIC_WORD g_trace_state[3];

namespace base {
namespace internal {

class DeleteTraceLogForTesting {
 public:
  static void Delete() {
    Singleton<trace_event::TraceLog,
              LeakySingletonTraits<trace_event::TraceLog>>::OnExit(0);
  }
};

}  // namespace internal

namespace trace_event {

namespace {

// Controls the number of trace events we will buffer in-memory
// before throwing them away.
const size_t kTraceBufferChunkSize = TraceBufferChunk::kTraceBufferChunkSize;

const size_t kTraceEventVectorBigBufferChunks =
    512000000 / kTraceBufferChunkSize;
static_assert(
    kTraceEventVectorBigBufferChunks <= TraceBufferChunk::kMaxChunkIndex,
    "Too many big buffer chunks");
const size_t kTraceEventVectorBufferChunks = 256000 / kTraceBufferChunkSize;
static_assert(
    kTraceEventVectorBufferChunks <= TraceBufferChunk::kMaxChunkIndex,
    "Too many vector buffer chunks");
const size_t kTraceEventRingBufferChunks = kTraceEventVectorBufferChunks / 4;

// ECHO_TO_CONSOLE needs a small buffer to hold the unfinished COMPLETE events.
const size_t kEchoToConsoleTraceEventBufferChunks = 256;

const size_t kTraceEventBufferSizeInBytes = 100 * 1024;
const int kThreadFlushTimeoutMs = 3000;

#define MAX_CATEGORY_GROUPS 200

// Parallel arrays g_category_groups and g_category_group_enabled are separate
// so that a pointer to a member of g_category_group_enabled can be easily
// converted to an index into g_category_groups. This allows macros to deal
// only with char enabled pointers from g_category_group_enabled, and we can
// convert internally to determine the category name from the char enabled
// pointer.
const char* g_category_groups[MAX_CATEGORY_GROUPS] = {
    "toplevel",
    "tracing already shutdown",
    "tracing categories exhausted; must increase MAX_CATEGORY_GROUPS",
    "__metadata"};

// The enabled flag is char instead of bool so that the API can be used from C.
unsigned char g_category_group_enabled[MAX_CATEGORY_GROUPS] = {0};

const char kEventNameWhitelist[] = "event_name_whitelist";

class EventNameFilter : public TraceLog::TraceEventFilter {
 public:
  EventNameFilter(const base::DictionaryValue* filter_args) {
    const base::ListValue* whitelist = nullptr;
    if (filter_args->GetList(kEventNameWhitelist, &whitelist)) {
      for (size_t i = 0; i < whitelist->GetSize(); ++i) {
        std::string event_name;
        if (!whitelist->GetString(i, &event_name))
          continue;

        whitelist_.insert(event_name);
      }
    }
  }

  bool FilterTraceEvent(const TraceEvent& trace_event) const override {
    return ContainsKey(whitelist_, trace_event.name());
  }

 private:
  std::unordered_set<std::string> whitelist_;
};

base::LazyInstance<
    std::list<std::unique_ptr<TraceLog::TraceEventFilter>>>::Leaky
    g_category_group_filter[MAX_CATEGORY_GROUPS] = {LAZY_INSTANCE_INITIALIZER};

// This filter is used to record trace events as pseudo stack for the heap
// profiler. It does not filter-out any events from the trace, ie. the behavior
// of trace events being added to TraceLog remains same: the events are added
// iff enabled for recording and not filtered-out by any other filter.
class HeapProfilerFilter : public TraceLog::TraceEventFilter {
 public:
  HeapProfilerFilter() {}

  bool FilterTraceEvent(const TraceEvent& trace_event) const override {
    if (AllocationContextTracker::capture_mode() !=
        AllocationContextTracker::CaptureMode::PSEUDO_STACK) {
      return true;
    }

    // TODO(primiano): Add support for events with copied name crbug.com/581079.
    if (trace_event.flags() & TRACE_EVENT_FLAG_COPY)
      return true;

    const char* category_name =
        TraceLog::GetCategoryGroupName(trace_event.category_group_enabled());
    if (trace_event.phase() == TRACE_EVENT_PHASE_BEGIN ||
        trace_event.phase() == TRACE_EVENT_PHASE_COMPLETE) {
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->PushPseudoStackFrame({category_name, trace_event.name()});
    } else if (trace_event.phase() == TRACE_EVENT_PHASE_END) {
      // The pop for |TRACE_EVENT_PHASE_COMPLETE| events is in |EndEvent|.
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->PopPseudoStackFrame({category_name, trace_event.name()});
    }
    // Do not filter-out any events and always return true. TraceLog adds the
    // event only if it is enabled for recording.
    return true;
  }

  void EndEvent(const char* name, const char* category_group) override {
    if (AllocationContextTracker::capture_mode() ==
        AllocationContextTracker::CaptureMode::PSEUDO_STACK) {
      AllocationContextTracker::GetInstanceForCurrentThread()
          ->PopPseudoStackFrame({category_group, name});
    }
  }
};

TraceLog::TraceEventFilterConstructorForTesting
    g_trace_event_filter_constructor_for_testing = nullptr;

// Indexes here have to match the g_category_groups array indexes above.
const int kCategoryAlreadyShutdown = 1;
const int kCategoryCategoriesExhausted = 2;
const int kCategoryMetadata = 3;
const int kNumBuiltinCategories = 4;
// Skip default categories.
base::subtle::AtomicWord g_category_index = kNumBuiltinCategories;

// The name of the current thread. This is used to decide if the current
// thread name has changed. We combine all the seen thread names into the
// output name for the thread.
LazyInstance<ThreadLocalPointer<const char>>::Leaky g_current_thread_name =
    LAZY_INSTANCE_INITIALIZER;

ThreadTicks ThreadNow() {
  return ThreadTicks::IsSupported() ? ThreadTicks::Now() : ThreadTicks();
}

template <typename T>
void InitializeMetadataEvent(TraceEvent* trace_event,
                             int thread_id,
                             const char* metadata_name,
                             const char* arg_name,
                             const T& value) {
  if (!trace_event)
    return;

  int num_args = 1;
  unsigned char arg_type;
  unsigned long long arg_value;
  ::trace_event_internal::SetTraceValue(value, &arg_type, &arg_value);
  trace_event->Initialize(
      thread_id,
      TimeTicks(),
      ThreadTicks(),
      TRACE_EVENT_PHASE_METADATA,
      &g_category_group_enabled[kCategoryMetadata],
      metadata_name,
      trace_event_internal::kGlobalScope,  // scope
      trace_event_internal::kNoId,  // id
      trace_event_internal::kNoId,  // bind_id
      num_args,
      &arg_name,
      &arg_type,
      &arg_value,
      nullptr,
      TRACE_EVENT_FLAG_NONE);
}

class AutoThreadLocalBoolean {
 public:
  explicit AutoThreadLocalBoolean(ThreadLocalBoolean* thread_local_boolean)
      : thread_local_boolean_(thread_local_boolean) {
    DCHECK(!thread_local_boolean_->Get());
    thread_local_boolean_->Set(true);
  }
  ~AutoThreadLocalBoolean() { thread_local_boolean_->Set(false); }

 private:
  ThreadLocalBoolean* thread_local_boolean_;
  DISALLOW_COPY_AND_ASSIGN(AutoThreadLocalBoolean);
};

// Use this function instead of TraceEventHandle constructor to keep the
// overhead of ScopedTracer (trace_event.h) constructor minimum.
void MakeHandle(uint32_t chunk_seq,
                size_t chunk_index,
                size_t event_index,
                TraceEventHandle* handle) {
  DCHECK(chunk_seq);
  DCHECK(chunk_index <= TraceBufferChunk::kMaxChunkIndex);
  DCHECK(event_index < TraceBufferChunk::kTraceBufferChunkSize);
  DCHECK(chunk_index <= std::numeric_limits<uint16_t>::max());
  handle->chunk_seq = chunk_seq;
  handle->chunk_index = static_cast<uint16_t>(chunk_index);
  handle->event_index = static_cast<uint16_t>(event_index);
}

uintptr_t GetCategoryIndex(const unsigned char* category_group_enabled) {
  // Calculate the index of the category group by finding
  // category_group_enabled in g_category_group_enabled array.
  uintptr_t category_begin =
      reinterpret_cast<uintptr_t>(g_category_group_enabled);
  uintptr_t category_ptr = reinterpret_cast<uintptr_t>(category_group_enabled);
  DCHECK(category_ptr >= category_begin);
  DCHECK(category_ptr < reinterpret_cast<uintptr_t>(g_category_group_enabled +
                                                    MAX_CATEGORY_GROUPS))
      << "out of bounds category pointer";
  uintptr_t category_index =
      (category_ptr - category_begin) / sizeof(g_category_group_enabled[0]);

  return category_index;
}

}  // namespace

// A helper class that allows the lock to be acquired in the middle of the scope
// and unlocks at the end of scope if locked.
class TraceLog::OptionalAutoLock {
 public:
  explicit OptionalAutoLock(Lock* lock) : lock_(lock), locked_(false) {}

  ~OptionalAutoLock() {
    if (locked_)
      lock_->Release();
  }

  void EnsureAcquired() {
    if (!locked_) {
      lock_->Acquire();
      locked_ = true;
    }
  }

 private:
  Lock* lock_;
  bool locked_;
  DISALLOW_COPY_AND_ASSIGN(OptionalAutoLock);
};

class TraceLog::ThreadLocalEventBuffer
    : public MessageLoop::DestructionObserver,
      public MemoryDumpProvider {
 public:
  explicit ThreadLocalEventBuffer(TraceLog* trace_log);
  ~ThreadLocalEventBuffer() override;

  TraceEvent* AddTraceEvent(TraceEventHandle* handle);

  TraceEvent* GetEventByHandle(TraceEventHandle handle) {
    if (!chunk_ || handle.chunk_seq != chunk_->seq() ||
        handle.chunk_index != chunk_index_) {
      return nullptr;
    }

    return chunk_->GetEventAt(handle.event_index);
  }

  int generation() const { return generation_; }

 private:
  // MessageLoop::DestructionObserver
  void WillDestroyCurrentMessageLoop() override;

  // MemoryDumpProvider implementation.
  bool OnMemoryDump(const MemoryDumpArgs& args,
                    ProcessMemoryDump* pmd) override;

  void FlushWhileLocked();

  void CheckThisIsCurrentBuffer() const {
    DCHECK(trace_log_->thread_local_event_buffer_.Get() == this);
  }

  // Since TraceLog is a leaky singleton, trace_log_ will always be valid
  // as long as the thread exists.
  TraceLog* trace_log_;
  std::unique_ptr<TraceBufferChunk> chunk_;
  size_t chunk_index_;
  int generation_;

  DISALLOW_COPY_AND_ASSIGN(ThreadLocalEventBuffer);
};

TraceLog::ThreadLocalEventBuffer::ThreadLocalEventBuffer(TraceLog* trace_log)
    : trace_log_(trace_log),
      chunk_index_(0),
      generation_(trace_log->generation()) {
  // ThreadLocalEventBuffer is created only if the thread has a message loop, so
  // the following message_loop won't be NULL.
  MessageLoop* message_loop = MessageLoop::current();
  message_loop->AddDestructionObserver(this);

  // This is to report the local memory usage when memory-infra is enabled.
  MemoryDumpManager::GetInstance()->RegisterDumpProvider(
      this, "ThreadLocalEventBuffer", ThreadTaskRunnerHandle::Get());

  AutoLock lock(trace_log->lock_);
  trace_log->thread_message_loops_.insert(message_loop);
}

TraceLog::ThreadLocalEventBuffer::~ThreadLocalEventBuffer() {
  CheckThisIsCurrentBuffer();
  MessageLoop::current()->RemoveDestructionObserver(this);
  MemoryDumpManager::GetInstance()->UnregisterDumpProvider(this);

  {
    AutoLock lock(trace_log_->lock_);
    FlushWhileLocked();
    trace_log_->thread_message_loops_.erase(MessageLoop::current());
  }
  trace_log_->thread_local_event_buffer_.Set(NULL);
}

TraceEvent* TraceLog::ThreadLocalEventBuffer::AddTraceEvent(
    TraceEventHandle* handle) {
  CheckThisIsCurrentBuffer();

  if (chunk_ && chunk_->IsFull()) {
    AutoLock lock(trace_log_->lock_);
    FlushWhileLocked();
    chunk_.reset();
  }
  if (!chunk_) {
    AutoLock lock(trace_log_->lock_);
    chunk_ = trace_log_->logged_events_->GetChunk(&chunk_index_);
    trace_log_->CheckIfBufferIsFullWhileLocked();
  }
  if (!chunk_)
    return NULL;

  size_t event_index;
  TraceEvent* trace_event = chunk_->AddTraceEvent(&event_index);
  if (trace_event && handle)
    MakeHandle(chunk_->seq(), chunk_index_, event_index, handle);

  return trace_event;
}

void TraceLog::ThreadLocalEventBuffer::WillDestroyCurrentMessageLoop() {
  delete this;
}

bool TraceLog::ThreadLocalEventBuffer::OnMemoryDump(const MemoryDumpArgs& args,
                                                    ProcessMemoryDump* pmd) {
  if (!chunk_)
    return true;
  std::string dump_base_name = StringPrintf(
      "tracing/thread_%d", static_cast<int>(PlatformThread::CurrentId()));
  TraceEventMemoryOverhead overhead;
  chunk_->EstimateTraceMemoryOverhead(&overhead);
  overhead.DumpInto(dump_base_name.c_str(), pmd);
  return true;
}

void TraceLog::ThreadLocalEventBuffer::FlushWhileLocked() {
  if (!chunk_)
    return;

  trace_log_->lock_.AssertAcquired();
  if (trace_log_->CheckGeneration(generation_)) {
    // Return the chunk to the buffer only if the generation matches.
    trace_log_->logged_events_->ReturnChunk(chunk_index_, std::move(chunk_));
  }
  // Otherwise this method may be called from the destructor, or TraceLog will
  // find the generation mismatch and delete this buffer soon.
}

struct TraceLog::RegisteredAsyncObserver {
  explicit RegisteredAsyncObserver(WeakPtr<AsyncEnabledStateObserver> observer)
      : observer(observer), task_runner(ThreadTaskRunnerHandle::Get()) {}
  ~RegisteredAsyncObserver() {}

  WeakPtr<AsyncEnabledStateObserver> observer;
  scoped_refptr<SequencedTaskRunner> task_runner;
};

TraceLogStatus::TraceLogStatus() : event_capacity(0), event_count(0) {}

TraceLogStatus::~TraceLogStatus() {}

// static
TraceLog* TraceLog::GetInstance() {
  return Singleton<TraceLog, LeakySingletonTraits<TraceLog>>::get();
}

TraceLog::TraceLog()
    : mode_(DISABLED),
      num_traces_recorded_(0),
      event_callback_(0),
      dispatching_to_observer_list_(false),
      process_sort_index_(0),
      process_id_hash_(0),
      process_id_(0),
      watch_category_(0),
      trace_options_(kInternalRecordUntilFull),
      sampling_thread_handle_(0),
      trace_config_(TraceConfig()),
      event_callback_trace_config_(TraceConfig()),
      thread_shared_chunk_index_(0),
      generation_(0),
      use_worker_thread_(false) {
  // Trace is enabled or disabled on one thread while other threads are
  // accessing the enabled flag. We don't care whether edge-case events are
  // traced or not, so we allow races on the enabled flag to keep the trace
  // macros fast.
  // TODO(jbates): ANNOTATE_BENIGN_RACE_SIZED crashes windows TSAN bots:
  // ANNOTATE_BENIGN_RACE_SIZED(g_category_group_enabled,
  //                            sizeof(g_category_group_enabled),
  //                           "trace_event category enabled");
  for (int i = 0; i < MAX_CATEGORY_GROUPS; ++i) {
    ANNOTATE_BENIGN_RACE(&g_category_group_enabled[i],
                         "trace_event category enabled");
  }
#if defined(OS_NACL)  // NaCl shouldn't expose the process id.
  SetProcessID(0);
#else
  SetProcessID(static_cast<int>(GetCurrentProcId()));
#endif

  logged_events_.reset(CreateTraceBuffer());

  MemoryDumpManager::GetInstance()->RegisterDumpProvider(this, "TraceLog",
                                                         nullptr);
}

TraceLog::~TraceLog() {}

void TraceLog::InitializeThreadLocalEventBufferIfSupported() {
  // A ThreadLocalEventBuffer needs the message loop
  // - to know when the thread exits;
  // - to handle the final flush.
  // For a thread without a message loop or the message loop may be blocked, the
  // trace events will be added into the main buffer directly.
  if (thread_blocks_message_loop_.Get() || !MessageLoop::current())
    return;
  HEAP_PROFILER_SCOPED_IGNORE;
  auto* thread_local_event_buffer = thread_local_event_buffer_.Get();
  if (thread_local_event_buffer &&
      !CheckGeneration(thread_local_event_buffer->generation())) {
    delete thread_local_event_buffer;
    thread_local_event_buffer = NULL;
  }
  if (!thread_local_event_buffer) {
    thread_local_event_buffer = new ThreadLocalEventBuffer(this);
    thread_local_event_buffer_.Set(thread_local_event_buffer);
  }
}

bool TraceLog::OnMemoryDump(const MemoryDumpArgs& args,
                            ProcessMemoryDump* pmd) {
  // TODO(ssid): Use MemoryDumpArgs to create light dumps when requested
  // (crbug.com/499731).
  TraceEventMemoryOverhead overhead;
  overhead.Add("TraceLog", sizeof(*this));
  {
    AutoLock lock(lock_);
    if (logged_events_)
      logged_events_->EstimateTraceMemoryOverhead(&overhead);

    for (auto& metadata_event : metadata_events_)
      metadata_event->EstimateTraceMemoryOverhead(&overhead);
  }
  overhead.AddSelf();
  overhead.DumpInto("tracing/main_trace_log", pmd);
  return true;
}

const unsigned char* TraceLog::GetCategoryGroupEnabled(
    const char* category_group) {
  TraceLog* tracelog = GetInstance();
  if (!tracelog) {
    DCHECK(!g_category_group_enabled[kCategoryAlreadyShutdown]);
    return &g_category_group_enabled[kCategoryAlreadyShutdown];
  }
  return tracelog->GetCategoryGroupEnabledInternal(category_group);
}

const char* TraceLog::GetCategoryGroupName(
    const unsigned char* category_group_enabled) {
  return g_category_groups[GetCategoryIndex(category_group_enabled)];
}

std::list<std::unique_ptr<TraceLog::TraceEventFilter>>* GetCategoryGroupFilter(
    const unsigned char* category_group_enabled) {
  return g_category_group_filter[GetCategoryIndex(category_group_enabled)]
      .Pointer();
}

void TraceLog::UpdateCategoryGroupEnabledFlag(size_t category_index) {
  unsigned char enabled_flag = 0;
  const char* category_group = g_category_groups[category_index];
  if (mode_ == RECORDING_MODE &&
      trace_config_.IsCategoryGroupEnabled(category_group)) {
    enabled_flag |= ENABLED_FOR_RECORDING;
  }

  if (event_callback_ &&
      event_callback_trace_config_.IsCategoryGroupEnabled(category_group)) {
    enabled_flag |= ENABLED_FOR_EVENT_CALLBACK;
  }

#if defined(OS_WIN)
  if (base::trace_event::TraceEventETWExport::IsCategoryGroupEnabled(
          category_group)) {
    enabled_flag |= ENABLED_FOR_ETW_EXPORT;
  }
#endif

  // TODO(primiano): this is a temporary workaround for catapult:#2341,
  // to guarantee that metadata events are always added even if the category
  // filter is "-*". See crbug.com/618054 for more details and long-term fix.
  if (mode_ == RECORDING_MODE && !strcmp(category_group, "__metadata"))
    enabled_flag |= ENABLED_FOR_RECORDING;

  // Having a filter is an exceptional case, so we avoid
  // the LazyInstance creation in the common case.
  if (!(g_category_group_filter[category_index] == nullptr))
    g_category_group_filter[category_index].Get().clear();

  for (const auto& event_filter : trace_config_.event_filters()) {
    if (event_filter.IsCategoryGroupEnabled(category_group)) {
      std::unique_ptr<TraceEventFilter> new_filter;

      if (event_filter.predicate_name() ==
          TraceEventFilter::kEventWhitelistPredicate) {
        new_filter = MakeUnique<EventNameFilter>(event_filter.filter_args());
      } else if (event_filter.predicate_name() ==
                 TraceEventFilter::kHeapProfilerPredicate) {
        new_filter = MakeUnique<HeapProfilerFilter>();
      } else if (event_filter.predicate_name() == "testing_predicate") {
        CHECK(g_trace_event_filter_constructor_for_testing);
        new_filter = g_trace_event_filter_constructor_for_testing();
      }

      if (new_filter) {
        g_category_group_filter[category_index].Get().push_back(
            std::move(new_filter));
        enabled_flag |= ENABLED_FOR_FILTERING;
      }
    }
  }

  g_category_group_enabled[category_index] = enabled_flag;
}

void TraceLog::UpdateCategoryGroupEnabledFlags() {
  size_t category_index = base::subtle::NoBarrier_Load(&g_category_index);
  for (size_t i = 0; i < category_index; i++)
    UpdateCategoryGroupEnabledFlag(i);
}

void TraceLog::UpdateSyntheticDelaysFromTraceConfig() {
  ResetTraceEventSyntheticDelays();
  const TraceConfig::StringList& delays =
      trace_config_.GetSyntheticDelayValues();
  TraceConfig::StringList::const_iterator ci;
  for (ci = delays.begin(); ci != delays.end(); ++ci) {
    StringTokenizer tokens(*ci, ";");
    if (!tokens.GetNext())
      continue;
    TraceEventSyntheticDelay* delay =
        TraceEventSyntheticDelay::Lookup(tokens.token());
    while (tokens.GetNext()) {
      std::string token = tokens.token();
      char* duration_end;
      double target_duration = strtod(token.c_str(), &duration_end);
      if (duration_end != token.c_str()) {
        delay->SetTargetDuration(TimeDelta::FromMicroseconds(
            static_cast<int64_t>(target_duration * 1e6)));
      } else if (token == "static") {
        delay->SetMode(TraceEventSyntheticDelay::STATIC);
      } else if (token == "oneshot") {
        delay->SetMode(TraceEventSyntheticDelay::ONE_SHOT);
      } else if (token == "alternating") {
        delay->SetMode(TraceEventSyntheticDelay::ALTERNATING);
      }
    }
  }
}

const unsigned char* TraceLog::GetCategoryGroupEnabledInternal(
    const char* category_group) {
  DCHECK(!strchr(category_group, '"'))
      << "Category groups may not contain double quote";
  // The g_category_groups is append only, avoid using a lock for the fast path.
  size_t current_category_index = base::subtle::Acquire_Load(&g_category_index);

  // Search for pre-existing category group.
  for (size_t i = 0; i < current_category_index; ++i) {
    if (strcmp(g_category_groups[i], category_group) == 0) {
      return &g_category_group_enabled[i];
    }
  }

  // This is the slow path: the lock is not held in the case above, so more
  // than one thread could have reached here trying to add the same category.
  // Only hold to lock when actually appending a new category, and
  // check the categories groups again.
  AutoLock lock(lock_);
  size_t category_index = base::subtle::Acquire_Load(&g_category_index);
  for (size_t i = 0; i < category_index; ++i) {
    if (strcmp(g_category_groups[i], category_group) == 0) {
      return &g_category_group_enabled[i];
    }
  }

  // Create a new category group.
  DCHECK(category_index < MAX_CATEGORY_GROUPS)
      << "must increase MAX_CATEGORY_GROUPS";
  unsigned char* category_group_enabled = nullptr;
  if (category_index < MAX_CATEGORY_GROUPS) {
    // Don't hold on to the category_group pointer, so that we can create
    // category groups with strings not known at compile time (this is
    // required by SetWatchEvent).
    const char* new_group = strdup(category_group);
    ANNOTATE_LEAKING_OBJECT_PTR(new_group);
    g_category_groups[category_index] = new_group;
    DCHECK(!g_category_group_enabled[category_index]);
    // Note that if both included and excluded patterns in the
    // TraceConfig are empty, we exclude nothing,
    // thereby enabling this category group.
    UpdateCategoryGroupEnabledFlag(category_index);
    category_group_enabled = &g_category_group_enabled[category_index];
    // Update the max index now.
    base::subtle::Release_Store(&g_category_index, category_index + 1);
  } else {
    category_group_enabled =
        &g_category_group_enabled[kCategoryCategoriesExhausted];
  }
  return category_group_enabled;
}

void TraceLog::GetKnownCategoryGroups(
    std::vector<std::string>* category_groups) {
  AutoLock lock(lock_);
  size_t category_index = base::subtle::NoBarrier_Load(&g_category_index);
  for (size_t i = kNumBuiltinCategories; i < category_index; i++)
    category_groups->push_back(g_category_groups[i]);
}

void TraceLog::SetEnabled(const TraceConfig& trace_config, Mode mode) {
  std::vector<EnabledStateObserver*> observer_list;
  std::map<AsyncEnabledStateObserver*, RegisteredAsyncObserver> observer_map;
  {
    AutoLock lock(lock_);

    // Can't enable tracing when Flush() is in progress.
    DCHECK(!flush_task_runner_);

    InternalTraceOptions new_options =
        GetInternalOptionsFromTraceConfig(trace_config);

    InternalTraceOptions old_options = trace_options();

    if (IsEnabled()) {
      if (new_options != old_options) {
        DLOG(ERROR) << "Attempting to re-enable tracing with a different "
                    << "set of options.";
      }

      if (mode != mode_) {
        DLOG(ERROR) << "Attempting to re-enable tracing with a different mode.";
      }

      trace_config_.Merge(trace_config);
      UpdateCategoryGroupEnabledFlags();
      return;
    }

    if (dispatching_to_observer_list_) {
      DLOG(ERROR)
          << "Cannot manipulate TraceLog::Enabled state from an observer.";
      return;
    }

    mode_ = mode;

    if (new_options != old_options) {
      subtle::NoBarrier_Store(&trace_options_, new_options);
      UseNextTraceBuffer();
    }

    num_traces_recorded_++;

    trace_config_ = TraceConfig(trace_config);
    UpdateCategoryGroupEnabledFlags();
    UpdateSyntheticDelaysFromTraceConfig();

    if (new_options & kInternalEnableSampling) {
      sampling_thread_.reset(new TraceSamplingThread);
      sampling_thread_->RegisterSampleBucket(
          &g_trace_state[0], "bucket0",
          Bind(&TraceSamplingThread::DefaultSamplingCallback));
      sampling_thread_->RegisterSampleBucket(
          &g_trace_state[1], "bucket1",
          Bind(&TraceSamplingThread::DefaultSamplingCallback));
      sampling_thread_->RegisterSampleBucket(
          &g_trace_state[2], "bucket2",
          Bind(&TraceSamplingThread::DefaultSamplingCallback));
      if (!PlatformThread::Create(0, sampling_thread_.get(),
                                  &sampling_thread_handle_)) {
        NOTREACHED() << "failed to create thread";
      }
    }

    dispatching_to_observer_list_ = true;
    observer_list = enabled_state_observer_list_;
    observer_map = async_observers_;
  }
  // Notify observers outside the lock in case they trigger trace events.
  for (EnabledStateObserver* observer : observer_list)
    observer->OnTraceLogEnabled();
  for (const auto& it : observer_map) {
    it.second.task_runner->PostTask(
        FROM_HERE, Bind(&AsyncEnabledStateObserver::OnTraceLogEnabled,
                        it.second.observer));
  }

  {
    AutoLock lock(lock_);
    dispatching_to_observer_list_ = false;
  }
}

void TraceLog::SetArgumentFilterPredicate(
    const ArgumentFilterPredicate& argument_filter_predicate) {
  AutoLock lock(lock_);
  DCHECK(!argument_filter_predicate.is_null());
  DCHECK(argument_filter_predicate_.is_null());
  argument_filter_predicate_ = argument_filter_predicate;
}

TraceLog::InternalTraceOptions TraceLog::GetInternalOptionsFromTraceConfig(
    const TraceConfig& config) {
  InternalTraceOptions ret =
      config.IsSamplingEnabled() ? kInternalEnableSampling : kInternalNone;
  if (config.IsArgumentFilterEnabled())
    ret |= kInternalEnableArgumentFilter;
  switch (config.GetTraceRecordMode()) {
    case RECORD_UNTIL_FULL:
      return ret | kInternalRecordUntilFull;
    case RECORD_CONTINUOUSLY:
      return ret | kInternalRecordContinuously;
    case ECHO_TO_CONSOLE:
      return ret | kInternalEchoToConsole;
    case RECORD_AS_MUCH_AS_POSSIBLE:
      return ret | kInternalRecordAsMuchAsPossible;
  }
  NOTREACHED();
  return kInternalNone;
}

TraceConfig TraceLog::GetCurrentTraceConfig() const {
  AutoLock lock(lock_);
  return trace_config_;
}

void TraceLog::SetDisabled() {
  AutoLock lock(lock_);
  SetDisabledWhileLocked();
}

void TraceLog::SetDisabledWhileLocked() {
  lock_.AssertAcquired();

  if (!IsEnabled())
    return;

  if (dispatching_to_observer_list_) {
    DLOG(ERROR)
        << "Cannot manipulate TraceLog::Enabled state from an observer.";
    return;
  }

  mode_ = DISABLED;

  if (sampling_thread_) {
    // Stop the sampling thread.
    sampling_thread_->Stop();
    lock_.Release();
    PlatformThread::Join(sampling_thread_handle_);
    lock_.Acquire();
    sampling_thread_handle_ = PlatformThreadHandle();
    sampling_thread_.reset();
  }

  trace_config_.Clear();
  subtle::NoBarrier_Store(&watch_category_, 0);
  watch_event_name_.clear();
  UpdateCategoryGroupEnabledFlags();
  AddMetadataEventsWhileLocked();

  // Remove metadata events so they will not get added to a subsequent trace.
  metadata_events_.clear();

  dispatching_to_observer_list_ = true;
  std::vector<EnabledStateObserver*> observer_list =
      enabled_state_observer_list_;
  std::map<AsyncEnabledStateObserver*, RegisteredAsyncObserver> observer_map =
      async_observers_;

  {
    // Dispatch to observers outside the lock in case the observer triggers a
    // trace event.
    AutoUnlock unlock(lock_);
    for (EnabledStateObserver* observer : observer_list)
      observer->OnTraceLogDisabled();
    for (const auto& it : observer_map) {
      it.second.task_runner->PostTask(
          FROM_HERE, Bind(&AsyncEnabledStateObserver::OnTraceLogDisabled,
                          it.second.observer));
    }
  }
  dispatching_to_observer_list_ = false;
}

int TraceLog::GetNumTracesRecorded() {
  AutoLock lock(lock_);
  if (!IsEnabled())
    return -1;
  return num_traces_recorded_;
}

void TraceLog::AddEnabledStateObserver(EnabledStateObserver* listener) {
  AutoLock lock(lock_);
  enabled_state_observer_list_.push_back(listener);
}

void TraceLog::RemoveEnabledStateObserver(EnabledStateObserver* listener) {
  AutoLock lock(lock_);
  std::vector<EnabledStateObserver*>::iterator it =
      std::find(enabled_state_observer_list_.begin(),
                enabled_state_observer_list_.end(), listener);
  if (it != enabled_state_observer_list_.end())
    enabled_state_observer_list_.erase(it);
}

bool TraceLog::HasEnabledStateObserver(EnabledStateObserver* listener) const {
  AutoLock lock(lock_);
  return ContainsValue(enabled_state_observer_list_, listener);
}

TraceLogStatus TraceLog::GetStatus() const {
  AutoLock lock(lock_);
  TraceLogStatus result;
  result.event_capacity = static_cast<uint32_t>(logged_events_->Capacity());
  result.event_count = static_cast<uint32_t>(logged_events_->Size());
  return result;
}

bool TraceLog::BufferIsFull() const {
  AutoLock lock(lock_);
  return logged_events_->IsFull();
}

TraceEvent* TraceLog::AddEventToThreadSharedChunkWhileLocked(
    TraceEventHandle* handle,
    bool check_buffer_is_full) {
  lock_.AssertAcquired();

  if (thread_shared_chunk_ && thread_shared_chunk_->IsFull()) {
    logged_events_->ReturnChunk(thread_shared_chunk_index_,
                                std::move(thread_shared_chunk_));
  }

  if (!thread_shared_chunk_) {
    thread_shared_chunk_ =
        logged_events_->GetChunk(&thread_shared_chunk_index_);
    if (check_buffer_is_full)
      CheckIfBufferIsFullWhileLocked();
  }
  if (!thread_shared_chunk_)
    return NULL;

  size_t event_index;
  TraceEvent* trace_event = thread_shared_chunk_->AddTraceEvent(&event_index);
  if (trace_event && handle) {
    MakeHandle(thread_shared_chunk_->seq(), thread_shared_chunk_index_,
               event_index, handle);
  }
  return trace_event;
}

void TraceLog::CheckIfBufferIsFullWhileLocked() {
  lock_.AssertAcquired();
  if (logged_events_->IsFull()) {
    if (buffer_limit_reached_timestamp_.is_null()) {
      buffer_limit_reached_timestamp_ = OffsetNow();
    }
    SetDisabledWhileLocked();
  }
}

void TraceLog::SetEventCallbackEnabled(const TraceConfig& trace_config,
                                       EventCallback cb) {
  AutoLock lock(lock_);
  subtle::NoBarrier_Store(&event_callback_,
                          reinterpret_cast<subtle::AtomicWord>(cb));
  event_callback_trace_config_ = trace_config;
  UpdateCategoryGroupEnabledFlags();
}

void TraceLog::SetEventCallbackDisabled() {
  AutoLock lock(lock_);
  subtle::NoBarrier_Store(&event_callback_, 0);
  UpdateCategoryGroupEnabledFlags();
}

// Flush() works as the following:
// 1. Flush() is called in thread A whose task runner is saved in
//    flush_task_runner_;
// 2. If thread_message_loops_ is not empty, thread A posts task to each message
//    loop to flush the thread local buffers; otherwise finish the flush;
// 3. FlushCurrentThread() deletes the thread local event buffer:
//    - The last batch of events of the thread are flushed into the main buffer;
//    - The message loop will be removed from thread_message_loops_;
//    If this is the last message loop, finish the flush;
// 4. If any thread hasn't finish its flush in time, finish the flush.
void TraceLog::Flush(const TraceLog::OutputCallback& cb,
                     bool use_worker_thread) {
  FlushInternal(cb, use_worker_thread, false);
}

void TraceLog::CancelTracing(const OutputCallback& cb) {
  SetDisabled();
  FlushInternal(cb, false, true);
}

void TraceLog::FlushInternal(const TraceLog::OutputCallback& cb,
                             bool use_worker_thread,
                             bool discard_events) {
  use_worker_thread_ = use_worker_thread;
  if (IsEnabled()) {
    // Can't flush when tracing is enabled because otherwise PostTask would
    // - generate more trace events;
    // - deschedule the calling thread on some platforms causing inaccurate
    //   timing of the trace events.
    scoped_refptr<RefCountedString> empty_result = new RefCountedString;
    if (!cb.is_null())
      cb.Run(empty_result, false);
    LOG(WARNING) << "Ignored TraceLog::Flush called when tracing is enabled";
    return;
  }

  int gen = generation();
  // Copy of thread_message_loops_ to be used without locking.
  std::vector<scoped_refptr<SingleThreadTaskRunner>>
      thread_message_loop_task_runners;
  {
    AutoLock lock(lock_);
    DCHECK(!flush_task_runner_);
    flush_task_runner_ = ThreadTaskRunnerHandle::IsSet()
                             ? ThreadTaskRunnerHandle::Get()
                             : nullptr;
    DCHECK(thread_message_loops_.empty() || flush_task_runner_);
    flush_output_callback_ = cb;

    if (thread_shared_chunk_) {
      logged_events_->ReturnChunk(thread_shared_chunk_index_,
                                  std::move(thread_shared_chunk_));
    }

    for (MessageLoop* loop : thread_message_loops_)
      thread_message_loop_task_runners.push_back(loop->task_runner());
  }

  if (!thread_message_loop_task_runners.empty()) {
    for (auto& task_runner : thread_message_loop_task_runners) {
      task_runner->PostTask(
          FROM_HERE, Bind(&TraceLog::FlushCurrentThread, Unretained(this),
                          gen, discard_events));
    }
    flush_task_runner_->PostDelayedTask(
        FROM_HERE, Bind(&TraceLog::OnFlushTimeout, Unretained(this), gen,
                        discard_events),
        TimeDelta::FromMilliseconds(kThreadFlushTimeoutMs));
    return;
  }

  FinishFlush(gen, discard_events);
}

// Usually it runs on a different thread.
void TraceLog::ConvertTraceEventsToTraceFormat(
    std::unique_ptr<TraceBuffer> logged_events,
    const OutputCallback& flush_output_callback,
    const ArgumentFilterPredicate& argument_filter_predicate) {
  if (flush_output_callback.is_null())
    return;

  HEAP_PROFILER_SCOPED_IGNORE;
  // The callback need to be called at least once even if there is no events
  // to let the caller know the completion of flush.
  scoped_refptr<RefCountedString> json_events_str_ptr = new RefCountedString();
  while (const TraceBufferChunk* chunk = logged_events->NextChunk()) {
    for (size_t j = 0; j < chunk->size(); ++j) {
      size_t size = json_events_str_ptr->size();
      if (size > kTraceEventBufferSizeInBytes) {
        flush_output_callback.Run(json_events_str_ptr, true);
        json_events_str_ptr = new RefCountedString();
      } else if (size) {
        json_events_str_ptr->data().append(",\n");
      }
      chunk->GetEventAt(j)->AppendAsJSON(&(json_events_str_ptr->data()),
                                         argument_filter_predicate);
    }
  }
  flush_output_callback.Run(json_events_str_ptr, false);
}

void TraceLog::FinishFlush(int generation, bool discard_events) {
  std::unique_ptr<TraceBuffer> previous_logged_events;
  OutputCallback flush_output_callback;
  ArgumentFilterPredicate argument_filter_predicate;

  if (!CheckGeneration(generation))
    return;

  {
    AutoLock lock(lock_);

    previous_logged_events.swap(logged_events_);
    UseNextTraceBuffer();
    thread_message_loops_.clear();

    flush_task_runner_ = NULL;
    flush_output_callback = flush_output_callback_;
    flush_output_callback_.Reset();

    if (trace_options() & kInternalEnableArgumentFilter) {
      CHECK(!argument_filter_predicate_.is_null());
      argument_filter_predicate = argument_filter_predicate_;
    }
  }

  if (discard_events) {
    if (!flush_output_callback.is_null()) {
      scoped_refptr<RefCountedString> empty_result = new RefCountedString;
      flush_output_callback.Run(empty_result, false);
    }
    return;
  }

  if (use_worker_thread_ &&
      WorkerPool::PostTask(
          FROM_HERE, Bind(&TraceLog::ConvertTraceEventsToTraceFormat,
                          Passed(&previous_logged_events),
                          flush_output_callback, argument_filter_predicate),
          true)) {
    return;
  }

  ConvertTraceEventsToTraceFormat(std::move(previous_logged_events),
                                  flush_output_callback,
                                  argument_filter_predicate);
}

// Run in each thread holding a local event buffer.
void TraceLog::FlushCurrentThread(int generation, bool discard_events) {
  {
    AutoLock lock(lock_);
    if (!CheckGeneration(generation) || !flush_task_runner_) {
      // This is late. The corresponding flush has finished.
      return;
    }
  }

  // This will flush the thread local buffer.
  delete thread_local_event_buffer_.Get();

  AutoLock lock(lock_);
  if (!CheckGeneration(generation) || !flush_task_runner_ ||
      !thread_message_loops_.empty())
    return;

  flush_task_runner_->PostTask(
      FROM_HERE, Bind(&TraceLog::FinishFlush, Unretained(this), generation,
                      discard_events));
}

void TraceLog::OnFlushTimeout(int generation, bool discard_events) {
  {
    AutoLock lock(lock_);
    if (!CheckGeneration(generation) || !flush_task_runner_) {
      // Flush has finished before timeout.
      return;
    }

    LOG(WARNING)
        << "The following threads haven't finished flush in time. "
           "If this happens stably for some thread, please call "
           "TraceLog::GetInstance()->SetCurrentThreadBlocksMessageLoop() from "
           "the thread to avoid its trace events from being lost.";
    for (hash_set<MessageLoop*>::const_iterator it =
             thread_message_loops_.begin();
         it != thread_message_loops_.end(); ++it) {
      LOG(WARNING) << "Thread: " << (*it)->GetThreadName();
    }
  }
  FinishFlush(generation, discard_events);
}

void TraceLog::UseNextTraceBuffer() {
  logged_events_.reset(CreateTraceBuffer());
  subtle::NoBarrier_AtomicIncrement(&generation_, 1);
  thread_shared_chunk_.reset();
  thread_shared_chunk_index_ = 0;
}

TraceEventHandle TraceLog::AddTraceEvent(
    char phase,
    const unsigned char* category_group_enabled,
    const char* name,
    const char* scope,
    unsigned long long id,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  int thread_id = static_cast<int>(base::PlatformThread::CurrentId());
  base::TimeTicks now = base::TimeTicks::Now();
  return AddTraceEventWithThreadIdAndTimestamp(
      phase,
      category_group_enabled,
      name,
      scope,
      id,
      trace_event_internal::kNoId,  // bind_id
      thread_id,
      now,
      num_args,
      arg_names,
      arg_types,
      arg_values,
      convertable_values,
      flags);
}

TraceEventHandle TraceLog::AddTraceEventWithBindId(
    char phase,
    const unsigned char* category_group_enabled,
    const char* name,
    const char* scope,
    unsigned long long id,
    unsigned long long bind_id,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  int thread_id = static_cast<int>(base::PlatformThread::CurrentId());
  base::TimeTicks now = base::TimeTicks::Now();
  return AddTraceEventWithThreadIdAndTimestamp(
      phase,
      category_group_enabled,
      name,
      scope,
      id,
      bind_id,
      thread_id,
      now,
      num_args,
      arg_names,
      arg_types,
      arg_values,
      convertable_values,
      flags | TRACE_EVENT_FLAG_HAS_CONTEXT_ID);
}

TraceEventHandle TraceLog::AddTraceEventWithProcessId(
    char phase,
    const unsigned char* category_group_enabled,
    const char* name,
    const char* scope,
    unsigned long long id,
    int process_id,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  base::TimeTicks now = base::TimeTicks::Now();
  return AddTraceEventWithThreadIdAndTimestamp(
      phase,
      category_group_enabled,
      name,
      scope,
      id,
      trace_event_internal::kNoId,  // bind_id
      process_id,
      now,
      num_args,
      arg_names,
      arg_types,
      arg_values,
      convertable_values,
      flags | TRACE_EVENT_FLAG_HAS_PROCESS_ID);
}

// Handle legacy calls to AddTraceEventWithThreadIdAndTimestamp
// with kNoId as bind_id
TraceEventHandle TraceLog::AddTraceEventWithThreadIdAndTimestamp(
    char phase,
    const unsigned char* category_group_enabled,
    const char* name,
    const char* scope,
    unsigned long long id,
    int thread_id,
    const TimeTicks& timestamp,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  return AddTraceEventWithThreadIdAndTimestamp(
      phase,
      category_group_enabled,
      name,
      scope,
      id,
      trace_event_internal::kNoId,  // bind_id
      thread_id,
      timestamp,
      num_args,
      arg_names,
      arg_types,
      arg_values,
      convertable_values,
      flags);
}

TraceEventHandle TraceLog::AddTraceEventWithThreadIdAndTimestamp(
    char phase,
    const unsigned char* category_group_enabled,
    const char* name,
    const char* scope,
    unsigned long long id,
    unsigned long long bind_id,
    int thread_id,
    const TimeTicks& timestamp,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  TraceEventHandle handle = {0, 0, 0};
  if (!*category_group_enabled)
    return handle;

  // Avoid re-entrance of AddTraceEvent. This may happen in GPU process when
  // ECHO_TO_CONSOLE is enabled: AddTraceEvent -> LOG(ERROR) ->
  // GpuProcessLogMessageHandler -> PostPendingTask -> TRACE_EVENT ...
  if (thread_is_in_trace_event_.Get())
    return handle;

  AutoThreadLocalBoolean thread_is_in_trace_event(&thread_is_in_trace_event_);

  DCHECK(name);
  DCHECK(!timestamp.is_null());

  if (flags & TRACE_EVENT_FLAG_MANGLE_ID) {
    if ((flags & TRACE_EVENT_FLAG_FLOW_IN) ||
        (flags & TRACE_EVENT_FLAG_FLOW_OUT))
      bind_id = MangleEventId(bind_id);
    id = MangleEventId(id);
  }

  TimeTicks offset_event_timestamp = OffsetTimestamp(timestamp);
  ThreadTicks thread_now = ThreadNow();

  // |thread_local_event_buffer_| can be null if the current thread doesn't have
  // a message loop or the message loop is blocked.
  InitializeThreadLocalEventBufferIfSupported();
  auto* thread_local_event_buffer = thread_local_event_buffer_.Get();

  // Check and update the current thread name only if the event is for the
  // current thread to avoid locks in most cases.
  if (thread_id == static_cast<int>(PlatformThread::CurrentId())) {
    const char* new_name =
        ThreadIdNameManager::GetInstance()->GetName(thread_id);
    // Check if the thread name has been set or changed since the previous
    // call (if any), but don't bother if the new name is empty. Note this will
    // not detect a thread name change within the same char* buffer address: we
    // favor common case performance over corner case correctness.
    if (new_name != g_current_thread_name.Get().Get() && new_name &&
        *new_name) {
      g_current_thread_name.Get().Set(new_name);

      AutoLock thread_info_lock(thread_info_lock_);

      hash_map<int, std::string>::iterator existing_name =
          thread_names_.find(thread_id);
      if (existing_name == thread_names_.end()) {
        // This is a new thread id, and a new name.
        thread_names_[thread_id] = new_name;
      } else {
        // This is a thread id that we've seen before, but potentially with a
        // new name.
        std::vector<StringPiece> existing_names = base::SplitStringPiece(
            existing_name->second, ",", base::KEEP_WHITESPACE,
            base::SPLIT_WANT_NONEMPTY);
        bool found = std::find(existing_names.begin(), existing_names.end(),
                               new_name) != existing_names.end();
        if (!found) {
          if (!existing_names.empty())
            existing_name->second.push_back(',');
          existing_name->second.append(new_name);
        }
      }
    }
  }

#if defined(OS_WIN)
  // This is done sooner rather than later, to avoid creating the event and
  // acquiring the lock, which is not needed for ETW as it's already threadsafe.
  if (*category_group_enabled & ENABLED_FOR_ETW_EXPORT)
    TraceEventETWExport::AddEvent(phase, category_group_enabled, name, id,
                                  num_args, arg_names, arg_types, arg_values,
                                  convertable_values);
#endif  // OS_WIN

  std::string console_message;
  std::unique_ptr<TraceEvent> filtered_trace_event;
  bool disabled_by_filters = false;
  if (*category_group_enabled & ENABLED_FOR_FILTERING) {
    std::unique_ptr<TraceEvent> new_trace_event(new TraceEvent);
    new_trace_event->Initialize(thread_id, offset_event_timestamp, thread_now,
                                phase, category_group_enabled, name, scope, id,
                                bind_id, num_args, arg_names, arg_types,
                                arg_values, convertable_values, flags);

    auto filter_list = GetCategoryGroupFilter(category_group_enabled);
    DCHECK(!filter_list->empty());

    disabled_by_filters = true;
    for (const auto& trace_event_filter : *filter_list) {
      if (trace_event_filter->FilterTraceEvent(*new_trace_event))
        disabled_by_filters = false;
    }

    if (!disabled_by_filters)
      filtered_trace_event = std::move(new_trace_event);
  }

  // If enabled for recording, the event should be added only if one of the
  // filters indicates or category is not enabled for filtering.
  if ((*category_group_enabled & ENABLED_FOR_RECORDING) &&
      !disabled_by_filters) {
    OptionalAutoLock lock(&lock_);

    TraceEvent* trace_event = NULL;
    if (thread_local_event_buffer) {
      trace_event = thread_local_event_buffer->AddTraceEvent(&handle);
    } else {
      lock.EnsureAcquired();
      trace_event = AddEventToThreadSharedChunkWhileLocked(&handle, true);
    }

    if (trace_event) {
      if (filtered_trace_event) {
        trace_event->MoveFrom(std::move(filtered_trace_event));
      } else {
        trace_event->Initialize(thread_id, offset_event_timestamp, thread_now,
                                phase, category_group_enabled, name, scope, id,
                                bind_id, num_args, arg_names, arg_types,
                                arg_values, convertable_values, flags);
      }

#if defined(OS_ANDROID)
      trace_event->SendToATrace();
#endif
    }

    if (trace_options() & kInternalEchoToConsole) {
      console_message = EventToConsoleMessage(
          phase == TRACE_EVENT_PHASE_COMPLETE ? TRACE_EVENT_PHASE_BEGIN : phase,
          timestamp, trace_event);
    }
  }

  if (!console_message.empty())
    LOG(ERROR) << console_message;

  if (reinterpret_cast<const unsigned char*>(
          subtle::NoBarrier_Load(&watch_category_)) == category_group_enabled) {
    bool event_name_matches;
    WatchEventCallback watch_event_callback_copy;
    {
      AutoLock lock(lock_);
      event_name_matches = watch_event_name_ == name;
      watch_event_callback_copy = watch_event_callback_;
    }
    if (event_name_matches) {
      if (!watch_event_callback_copy.is_null())
        watch_event_callback_copy.Run();
    }
  }

  if (*category_group_enabled & ENABLED_FOR_EVENT_CALLBACK) {
    EventCallback event_callback = reinterpret_cast<EventCallback>(
        subtle::NoBarrier_Load(&event_callback_));
    if (event_callback) {
      event_callback(
          offset_event_timestamp,
          phase == TRACE_EVENT_PHASE_COMPLETE ? TRACE_EVENT_PHASE_BEGIN : phase,
          category_group_enabled, name, scope, id, num_args, arg_names,
          arg_types, arg_values, flags);
    }
  }

  return handle;
}

void TraceLog::AddMetadataEvent(
    const unsigned char* category_group_enabled,
    const char* name,
    int num_args,
    const char** arg_names,
    const unsigned char* arg_types,
    const unsigned long long* arg_values,
    std::unique_ptr<ConvertableToTraceFormat>* convertable_values,
    unsigned int flags) {
  HEAP_PROFILER_SCOPED_IGNORE;
  std::unique_ptr<TraceEvent> trace_event(new TraceEvent);
  int thread_id = static_cast<int>(base::PlatformThread::CurrentId());
  ThreadTicks thread_now = ThreadNow();
  TimeTicks now = OffsetNow();
  AutoLock lock(lock_);
  trace_event->Initialize(
      thread_id, now, thread_now, TRACE_EVENT_PHASE_METADATA,
      category_group_enabled, name,
      trace_event_internal::kGlobalScope,  // scope
      trace_event_internal::kNoId,         // id
      trace_event_internal::kNoId,         // bind_id
      num_args, arg_names, arg_types, arg_values, convertable_values, flags);
  metadata_events_.push_back(std::move(trace_event));
}

// May be called when a COMPELETE event ends and the unfinished event has been
// recycled (phase == TRACE_EVENT_PHASE_END and trace_event == NULL).
std::string TraceLog::EventToConsoleMessage(unsigned char phase,
                                            const TimeTicks& timestamp,
                                            TraceEvent* trace_event) {
  HEAP_PROFILER_SCOPED_IGNORE;
  AutoLock thread_info_lock(thread_info_lock_);

  // The caller should translate TRACE_EVENT_PHASE_COMPLETE to
  // TRACE_EVENT_PHASE_BEGIN or TRACE_EVENT_END.
  DCHECK(phase != TRACE_EVENT_PHASE_COMPLETE);

  TimeDelta duration;
  int thread_id =
      trace_event ? trace_event->thread_id() : PlatformThread::CurrentId();
  if (phase == TRACE_EVENT_PHASE_END) {
    duration = timestamp - thread_event_start_times_[thread_id].top();
    thread_event_start_times_[thread_id].pop();
  }

  std::string thread_name = thread_names_[thread_id];
  if (thread_colors_.find(thread_name) == thread_colors_.end())
    thread_colors_[thread_name] = (thread_colors_.size() % 6) + 1;

  std::ostringstream log;
  log << base::StringPrintf("%s: \x1b[0;3%dm", thread_name.c_str(),
                            thread_colors_[thread_name]);

  size_t depth = 0;
  auto it = thread_event_start_times_.find(thread_id);
  if (it != thread_event_start_times_.end())
    depth = it->second.size();

  for (size_t i = 0; i < depth; ++i)
    log << "| ";

  if (trace_event)
    trace_event->AppendPrettyPrinted(&log);
  if (phase == TRACE_EVENT_PHASE_END)
    log << base::StringPrintf(" (%.3f ms)", duration.InMillisecondsF());

  log << "\x1b[0;m";

  if (phase == TRACE_EVENT_PHASE_BEGIN)
    thread_event_start_times_[thread_id].push(timestamp);

  return log.str();
}

void TraceLog::EndFilteredEvent(const unsigned char* category_group_enabled,
                                const char* name,
                                TraceEventHandle handle) {
  auto filter_list = GetCategoryGroupFilter(category_group_enabled);
  DCHECK(!filter_list->empty());

  for (const auto& trace_event_filter : *filter_list) {
    trace_event_filter->EndEvent(name,
                                 GetCategoryGroupName(category_group_enabled));
  }
}

void TraceLog::UpdateTraceEventDuration(
    const unsigned char* category_group_enabled,
    const char* name,
    TraceEventHandle handle) {
  char category_group_enabled_local = *category_group_enabled;
  if (!category_group_enabled_local)
    return;

  // Avoid re-entrance of AddTraceEvent. This may happen in GPU process when
  // ECHO_TO_CONSOLE is enabled: AddTraceEvent -> LOG(ERROR) ->
  // GpuProcessLogMessageHandler -> PostPendingTask -> TRACE_EVENT ...
  if (thread_is_in_trace_event_.Get())
    return;

  AutoThreadLocalBoolean thread_is_in_trace_event(&thread_is_in_trace_event_);

  ThreadTicks thread_now = ThreadNow();
  TimeTicks now = OffsetNow();

#if defined(OS_WIN)
  // Generate an ETW event that marks the end of a complete event.
  if (category_group_enabled_local & ENABLED_FOR_ETW_EXPORT)
    TraceEventETWExport::AddCompleteEndEvent(name);
#endif  // OS_WIN

  std::string console_message;
  if (category_group_enabled_local & ENABLED_FOR_RECORDING) {
    OptionalAutoLock lock(&lock_);

    TraceEvent* trace_event = GetEventByHandleInternal(handle, &lock);
    if (trace_event) {
      DCHECK(trace_event->phase() == TRACE_EVENT_PHASE_COMPLETE);
      // TEMP(oysteine) to debug crbug.com/638744
      if (trace_event->duration().ToInternalValue() != -1) {
        DVLOG(1) << "TraceHandle: chunk_seq " << handle.chunk_seq
                 << ", chunk_index " << handle.chunk_index << ", event_index "
                 << handle.event_index;

        std::string serialized_event;
        trace_event->AppendAsJSON(&serialized_event, ArgumentFilterPredicate());
        DVLOG(1) << "TraceEvent: " << serialized_event;
        lock_.AssertAcquired();
      }

      trace_event->UpdateDuration(now, thread_now);
#if defined(OS_ANDROID)
      trace_event->SendToATrace();
#endif
    }

    if (trace_options() & kInternalEchoToConsole) {
      console_message =
          EventToConsoleMessage(TRACE_EVENT_PHASE_END, now, trace_event);
    }
  }

  if (!console_message.empty())
    LOG(ERROR) << console_message;

  if (category_group_enabled_local & ENABLED_FOR_EVENT_CALLBACK) {
    EventCallback event_callback = reinterpret_cast<EventCallback>(
        subtle::NoBarrier_Load(&event_callback_));
    if (event_callback) {
      event_callback(
        now, TRACE_EVENT_PHASE_END, category_group_enabled, name,
        trace_event_internal::kGlobalScope, trace_event_internal::kNoId, 0,
        nullptr, nullptr, nullptr, TRACE_EVENT_FLAG_NONE);
    }
  }
}

void TraceLog::SetWatchEvent(const std::string& category_name,
                             const std::string& event_name,
                             const WatchEventCallback& callback) {
  const unsigned char* category =
      GetCategoryGroupEnabled(category_name.c_str());
  AutoLock lock(lock_);
  subtle::NoBarrier_Store(&watch_category_,
                          reinterpret_cast<subtle::AtomicWord>(category));
  watch_event_name_ = event_name;
  watch_event_callback_ = callback;
}

void TraceLog::CancelWatchEvent() {
  AutoLock lock(lock_);
  subtle::NoBarrier_Store(&watch_category_, 0);
  watch_event_name_.clear();
  watch_event_callback_.Reset();
}

uint64_t TraceLog::MangleEventId(uint64_t id) {
  return id ^ process_id_hash_;
}

void TraceLog::AddMetadataEventsWhileLocked() {
  lock_.AssertAcquired();

  // Move metadata added by |AddMetadataEvent| into the trace log.
  while (!metadata_events_.empty()) {
    TraceEvent* event = AddEventToThreadSharedChunkWhileLocked(nullptr, false);
    event->MoveFrom(std::move(metadata_events_.back()));
    metadata_events_.pop_back();
  }

#if !defined(OS_NACL)  // NaCl shouldn't expose the process id.
  InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                          0, "num_cpus", "number",
                          base::SysInfo::NumberOfProcessors());
#endif

  int current_thread_id = static_cast<int>(base::PlatformThread::CurrentId());
  if (process_sort_index_ != 0) {
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            current_thread_id, "process_sort_index",
                            "sort_index", process_sort_index_);
  }

  if (!process_name_.empty()) {
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            current_thread_id, "process_name", "name",
                            process_name_);
  }

  if (!process_labels_.empty()) {
    std::vector<std::string> labels;
    for (const auto& it : process_labels_)
      labels.push_back(it.second);
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            current_thread_id, "process_labels", "labels",
                            base::JoinString(labels, ","));
  }

  // Thread sort indices.
  for (const auto& it : thread_sort_indices_) {
    if (it.second == 0)
      continue;
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            it.first, "thread_sort_index", "sort_index",
                            it.second);
  }

  // Thread names.
  AutoLock thread_info_lock(thread_info_lock_);
  for (const auto& it : thread_names_) {
    if (it.second.empty())
      continue;
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            it.first, "thread_name", "name", it.second);
  }

  // If buffer is full, add a metadata record to report this.
  if (!buffer_limit_reached_timestamp_.is_null()) {
    InitializeMetadataEvent(AddEventToThreadSharedChunkWhileLocked(NULL, false),
                            current_thread_id, "trace_buffer_overflowed",
                            "overflowed_at_ts",
                            buffer_limit_reached_timestamp_);
  }
}

void TraceLog::WaitSamplingEventForTesting() {
  if (!sampling_thread_)
    return;
  sampling_thread_->WaitSamplingEventForTesting();
}

void TraceLog::DeleteForTesting() {
  internal::DeleteTraceLogForTesting::Delete();
}

void TraceLog::SetTraceEventFilterConstructorForTesting(
    TraceEventFilterConstructorForTesting predicate) {
  g_trace_event_filter_constructor_for_testing = predicate;
}

TraceEvent* TraceLog::GetEventByHandle(TraceEventHandle handle) {
  return GetEventByHandleInternal(handle, NULL);
}

TraceEvent* TraceLog::GetEventByHandleInternal(TraceEventHandle handle,
                                               OptionalAutoLock* lock) {
  if (!handle.chunk_seq)
    return NULL;

  DCHECK(handle.chunk_seq);
  DCHECK(handle.chunk_index <= TraceBufferChunk::kMaxChunkIndex);
  DCHECK(handle.event_index < TraceBufferChunk::kTraceBufferChunkSize);

  if (thread_local_event_buffer_.Get()) {
    TraceEvent* trace_event =
        thread_local_event_buffer_.Get()->GetEventByHandle(handle);
    if (trace_event)
      return trace_event;
  }

  // The event has been out-of-control of the thread local buffer.
  // Try to get the event from the main buffer with a lock.
  if (lock)
    lock->EnsureAcquired();

  if (thread_shared_chunk_ &&
      handle.chunk_index == thread_shared_chunk_index_) {
    return handle.chunk_seq == thread_shared_chunk_->seq()
               ? thread_shared_chunk_->GetEventAt(handle.event_index)
               : NULL;
  }

  return logged_events_->GetEventByHandle(handle);
}

void TraceLog::SetProcessID(int process_id) {
  process_id_ = process_id;
  // Create a FNV hash from the process ID for XORing.
  // See http://isthe.com/chongo/tech/comp/fnv/ for algorithm details.
  const unsigned long long kOffsetBasis = 14695981039346656037ull;
  const unsigned long long kFnvPrime = 1099511628211ull;
  const unsigned long long pid = static_cast<unsigned long long>(process_id_);
  process_id_hash_ = (kOffsetBasis ^ pid) * kFnvPrime;
}

void TraceLog::SetProcessSortIndex(int sort_index) {
  AutoLock lock(lock_);
  process_sort_index_ = sort_index;
}

void TraceLog::SetProcessName(const char* process_name) {
  AutoLock lock(lock_);
  process_name_ = process_name;
}

void TraceLog::UpdateProcessLabel(int label_id,
                                  const std::string& current_label) {
  if (!current_label.length())
    return RemoveProcessLabel(label_id);

  AutoLock lock(lock_);
  process_labels_[label_id] = current_label;
}

void TraceLog::RemoveProcessLabel(int label_id) {
  AutoLock lock(lock_);
  process_labels_.erase(label_id);
}

void TraceLog::SetThreadSortIndex(PlatformThreadId thread_id, int sort_index) {
  AutoLock lock(lock_);
  thread_sort_indices_[static_cast<int>(thread_id)] = sort_index;
}

void TraceLog::SetTimeOffset(TimeDelta offset) {
  time_offset_ = offset;
}

size_t TraceLog::GetObserverCountForTest() const {
  return enabled_state_observer_list_.size();
}

void TraceLog::SetCurrentThreadBlocksMessageLoop() {
  thread_blocks_message_loop_.Set(true);
  // This will flush the thread local buffer.
  delete thread_local_event_buffer_.Get();
}

TraceBuffer* TraceLog::CreateTraceBuffer() {
  HEAP_PROFILER_SCOPED_IGNORE;
  InternalTraceOptions options = trace_options();
  if (options & kInternalRecordContinuously) {
    return TraceBuffer::CreateTraceBufferRingBuffer(
        kTraceEventRingBufferChunks);
  }
  if (options & kInternalEchoToConsole) {
    return TraceBuffer::CreateTraceBufferRingBuffer(
        kEchoToConsoleTraceEventBufferChunks);
  }
  if (options & kInternalRecordAsMuchAsPossible) {
    return TraceBuffer::CreateTraceBufferVectorOfSize(
        kTraceEventVectorBigBufferChunks);
  }
  return TraceBuffer::CreateTraceBufferVectorOfSize(
      kTraceEventVectorBufferChunks);
}

#if defined(OS_WIN)
void TraceLog::UpdateETWCategoryGroupEnabledFlags() {
  AutoLock lock(lock_);
  size_t category_index = base::subtle::NoBarrier_Load(&g_category_index);
  // Go through each category and set/clear the ETW bit depending on whether the
  // category is enabled.
  for (size_t i = 0; i < category_index; i++) {
    const char* category_group = g_category_groups[i];
    DCHECK(category_group);
    if (base::trace_event::TraceEventETWExport::IsCategoryGroupEnabled(
            category_group)) {
      g_category_group_enabled[i] |= ENABLED_FOR_ETW_EXPORT;
    } else {
      g_category_group_enabled[i] &= ~ENABLED_FOR_ETW_EXPORT;
    }
  }
}
#endif  // defined(OS_WIN)

void ConvertableToTraceFormat::EstimateTraceMemoryOverhead(
    TraceEventMemoryOverhead* overhead) {
  overhead->Add("ConvertableToTraceFormat(Unknown)", sizeof(*this));
}

void TraceLog::AddAsyncEnabledStateObserver(
    WeakPtr<AsyncEnabledStateObserver> listener) {
  AutoLock lock(lock_);
  async_observers_.insert(
      std::make_pair(listener.get(), RegisteredAsyncObserver(listener)));
}

void TraceLog::RemoveAsyncEnabledStateObserver(
    AsyncEnabledStateObserver* listener) {
  AutoLock lock(lock_);
  async_observers_.erase(listener);
}

bool TraceLog::HasAsyncEnabledStateObserver(
    AsyncEnabledStateObserver* listener) const {
  AutoLock lock(lock_);
  return ContainsKey(async_observers_, listener);
}

}  // namespace trace_event
}  // namespace base

namespace trace_event_internal {

ScopedTraceBinaryEfficient::ScopedTraceBinaryEfficient(
    const char* category_group,
    const char* name) {
  // The single atom works because for now the category_group can only be "gpu".
  DCHECK_EQ(strcmp(category_group, "gpu"), 0);
  static TRACE_EVENT_API_ATOMIC_WORD atomic = 0;
  INTERNAL_TRACE_EVENT_GET_CATEGORY_INFO_CUSTOM_VARIABLES(
      category_group, atomic, category_group_enabled_);
  name_ = name;
  if (*category_group_enabled_) {
    event_handle_ =
        TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_THREAD_ID_AND_TIMESTAMP(
            TRACE_EVENT_PHASE_COMPLETE,
            category_group_enabled_,
            name,
            trace_event_internal::kGlobalScope,  // scope
            trace_event_internal::kNoId,  // id
            static_cast<int>(base::PlatformThread::CurrentId()),  // thread_id
            base::TimeTicks::Now(),
            trace_event_internal::kZeroNumArgs,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            TRACE_EVENT_FLAG_NONE);
  }
}

ScopedTraceBinaryEfficient::~ScopedTraceBinaryEfficient() {
  if (*category_group_enabled_) {
    TRACE_EVENT_API_UPDATE_TRACE_EVENT_DURATION(category_group_enabled_, name_,
                                                event_handle_);
  }
}

}  // namespace trace_event_internal
