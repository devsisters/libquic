// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_dump_manager.h"

#include <algorithm>
#include <utility>

#include "base/allocator/features.h"
#include "base/atomic_sequence_num.h"
#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/debug/debugging_flags.h"
#include "base/debug/stack_trace.h"
#include "base/memory/ptr_util.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/trace_event/heap_profiler.h"
#include "base/trace_event/heap_profiler_allocation_context_tracker.h"
#include "base/trace_event/heap_profiler_stack_frame_deduplicator.h"
#include "base/trace_event/heap_profiler_type_name_deduplicator.h"
#include "base/trace_event/malloc_dump_provider.h"
#include "base/trace_event/memory_dump_provider.h"
#include "base/trace_event/memory_dump_session_state.h"
#include "base/trace_event/memory_infra_background_whitelist.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/trace_event_argument.h"
#include "build/build_config.h"

#if defined(OS_ANDROID)
#include "base/trace_event/java_heap_dump_provider_android.h"
#endif

namespace base {
namespace trace_event {

namespace {

const int kTraceEventNumArgs = 1;
const char* kTraceEventArgNames[] = {"dumps"};
const unsigned char kTraceEventArgTypes[] = {TRACE_VALUE_TYPE_CONVERTABLE};

StaticAtomicSequenceNumber g_next_guid;
MemoryDumpManager* g_instance_for_testing = nullptr;

// Callback wrapper to hook upon the completion of RequestGlobalDump() and
// inject trace markers.
void OnGlobalDumpDone(MemoryDumpCallback wrapped_callback,
                      uint64_t dump_guid,
                      bool success) {
  TRACE_EVENT_NESTABLE_ASYNC_END1(
      MemoryDumpManager::kTraceCategory, "GlobalMemoryDump",
      TRACE_ID_MANGLE(dump_guid), "success", success);

  if (!wrapped_callback.is_null()) {
    wrapped_callback.Run(dump_guid, success);
    wrapped_callback.Reset();
  }
}

// Proxy class which wraps a ConvertableToTraceFormat owned by the
// |session_state| into a proxy object that can be added to the trace event log.
// This is to solve the problem that the MemoryDumpSessionState is refcounted
// but the tracing subsystem wants a std::unique_ptr<ConvertableToTraceFormat>.
template <typename T>
struct SessionStateConvertableProxy : public ConvertableToTraceFormat {
  using GetterFunctPtr = T* (MemoryDumpSessionState::*)() const;

  SessionStateConvertableProxy(
      scoped_refptr<MemoryDumpSessionState> session_state,
      GetterFunctPtr getter_function)
      : session_state(session_state), getter_function(getter_function) {}

  void AppendAsTraceFormat(std::string* out) const override {
    return (session_state.get()->*getter_function)()->AppendAsTraceFormat(out);
  }

  void EstimateTraceMemoryOverhead(
      TraceEventMemoryOverhead* overhead) override {
    return (session_state.get()->*getter_function)()
        ->EstimateTraceMemoryOverhead(overhead);
  }

  scoped_refptr<MemoryDumpSessionState> session_state;
  GetterFunctPtr const getter_function;
};

}  // namespace

// static
const char* const MemoryDumpManager::kTraceCategory =
    TRACE_DISABLED_BY_DEFAULT("memory-infra");

// static
const char* const MemoryDumpManager::kLogPrefix = "Memory-infra dump";

// static
const int MemoryDumpManager::kMaxConsecutiveFailuresCount = 3;

// static
const uint64_t MemoryDumpManager::kInvalidTracingProcessId = 0;

// static
const char* const MemoryDumpManager::kSystemAllocatorPoolName =
#if defined(MALLOC_MEMORY_TRACING_SUPPORTED)
    MallocDumpProvider::kAllocatedObjects;
#else
    nullptr;
#endif

// static
MemoryDumpManager* MemoryDumpManager::GetInstance() {
  if (g_instance_for_testing)
    return g_instance_for_testing;

  return Singleton<MemoryDumpManager,
                   LeakySingletonTraits<MemoryDumpManager>>::get();
}

// static
void MemoryDumpManager::SetInstanceForTesting(MemoryDumpManager* instance) {
  g_instance_for_testing = instance;
}

MemoryDumpManager::MemoryDumpManager()
    : delegate_(nullptr),
      is_coordinator_(false),
      memory_tracing_enabled_(0),
      tracing_process_id_(kInvalidTracingProcessId),
      dumper_registrations_ignored_for_testing_(false),
      heap_profiling_enabled_(false) {
  g_next_guid.GetNext();  // Make sure that first guid is not zero.

  // At this point the command line may not be initialized but we try to
  // enable the heap profiler to capture allocations as soon as possible.
  EnableHeapProfilingIfNeeded();
}

MemoryDumpManager::~MemoryDumpManager() {
  TraceLog::GetInstance()->RemoveEnabledStateObserver(this);
}

void MemoryDumpManager::EnableHeapProfilingIfNeeded() {
  if (heap_profiling_enabled_)
    return;

  if (!CommandLine::InitializedForCurrentProcess() ||
      !CommandLine::ForCurrentProcess()->HasSwitch(
          switches::kEnableHeapProfiling))
    return;

  std::string profiling_mode = CommandLine::ForCurrentProcess()
      ->GetSwitchValueASCII(switches::kEnableHeapProfiling);
  if (profiling_mode == "") {
    AllocationContextTracker::SetCaptureMode(
        AllocationContextTracker::CaptureMode::PSEUDO_STACK);
  }
  else if (profiling_mode == switches::kEnableHeapProfilingModeNative) {
#if HAVE_TRACE_STACK_FRAME_POINTERS && \
    (BUILDFLAG(ENABLE_PROFILING) || !defined(NDEBUG))
    // We need frame pointers for native tracing to work, and they are
    // enabled in profiling and debug builds.
    AllocationContextTracker::SetCaptureMode(
        AllocationContextTracker::CaptureMode::NATIVE_STACK);
#else
    CHECK(false) << "'" << profiling_mode << "' mode for "
                 << switches::kEnableHeapProfiling << " flag is not supported "
                 << "for this platform / build type.";
#endif
  } else {
    CHECK(false) << "Invalid mode '" << profiling_mode << "' for "
               << switches::kEnableHeapProfiling << " flag.";
  }

  for (auto mdp : dump_providers_)
    mdp->dump_provider->OnHeapProfilingEnabled(true);
  heap_profiling_enabled_ = true;
}

void MemoryDumpManager::Initialize(MemoryDumpManagerDelegate* delegate,
                                   bool is_coordinator) {
  {
    AutoLock lock(lock_);
    DCHECK(delegate);
    DCHECK(!delegate_);
    delegate_ = delegate;
    is_coordinator_ = is_coordinator;
    EnableHeapProfilingIfNeeded();
  }

// Enable the core dump providers.
#if defined(MALLOC_MEMORY_TRACING_SUPPORTED)
  RegisterDumpProvider(MallocDumpProvider::GetInstance(), "Malloc", nullptr);
#endif

#if defined(OS_ANDROID)
  RegisterDumpProvider(JavaHeapDumpProvider::GetInstance(), "JavaHeap",
                       nullptr);
#endif

  // If tracing was enabled before initializing MemoryDumpManager, we missed the
  // OnTraceLogEnabled() event. Synthetize it so we can late-join the party.
  bool is_tracing_already_enabled = TraceLog::GetInstance()->IsEnabled();
  TRACE_EVENT0(kTraceCategory, "init");  // Add to trace-viewer category list.
  TraceLog::GetInstance()->AddEnabledStateObserver(this);
  if (is_tracing_already_enabled)
    OnTraceLogEnabled();
}

void MemoryDumpManager::RegisterDumpProvider(
    MemoryDumpProvider* mdp,
    const char* name,
    scoped_refptr<SingleThreadTaskRunner> task_runner,
    MemoryDumpProvider::Options options) {
  options.dumps_on_single_thread_task_runner = true;
  RegisterDumpProviderInternal(mdp, name, std::move(task_runner), options);
}

void MemoryDumpManager::RegisterDumpProvider(
    MemoryDumpProvider* mdp,
    const char* name,
    scoped_refptr<SingleThreadTaskRunner> task_runner) {
  // Set |dumps_on_single_thread_task_runner| to true because all providers
  // without task runner are run on dump thread.
  MemoryDumpProvider::Options options;
  options.dumps_on_single_thread_task_runner = true;
  RegisterDumpProviderInternal(mdp, name, std::move(task_runner), options);
}

void MemoryDumpManager::RegisterDumpProviderWithSequencedTaskRunner(
    MemoryDumpProvider* mdp,
    const char* name,
    scoped_refptr<SequencedTaskRunner> task_runner,
    MemoryDumpProvider::Options options) {
  DCHECK(task_runner);
  options.dumps_on_single_thread_task_runner = false;
  RegisterDumpProviderInternal(mdp, name, std::move(task_runner), options);
}

void MemoryDumpManager::RegisterDumpProviderInternal(
    MemoryDumpProvider* mdp,
    const char* name,
    scoped_refptr<SequencedTaskRunner> task_runner,
    const MemoryDumpProvider::Options& options) {
  if (dumper_registrations_ignored_for_testing_)
    return;

  bool whitelisted_for_background_mode = IsMemoryDumpProviderWhitelisted(name);
  scoped_refptr<MemoryDumpProviderInfo> mdpinfo =
      new MemoryDumpProviderInfo(mdp, name, std::move(task_runner), options,
                                 whitelisted_for_background_mode);

  {
    AutoLock lock(lock_);
    bool already_registered = !dump_providers_.insert(mdpinfo).second;
    // This actually happens in some tests which don't have a clean tear-down
    // path for RenderThreadImpl::Init().
    if (already_registered)
      return;
  }

  if (heap_profiling_enabled_)
    mdp->OnHeapProfilingEnabled(true);
}

void MemoryDumpManager::UnregisterDumpProvider(MemoryDumpProvider* mdp) {
  UnregisterDumpProviderInternal(mdp, false /* delete_async */);
}

void MemoryDumpManager::UnregisterAndDeleteDumpProviderSoon(
    std::unique_ptr<MemoryDumpProvider> mdp) {
  UnregisterDumpProviderInternal(mdp.release(), true /* delete_async */);
}

void MemoryDumpManager::UnregisterDumpProviderInternal(
    MemoryDumpProvider* mdp,
    bool take_mdp_ownership_and_delete_async) {
  std::unique_ptr<MemoryDumpProvider> owned_mdp;
  if (take_mdp_ownership_and_delete_async)
    owned_mdp.reset(mdp);

  AutoLock lock(lock_);

  auto mdp_iter = dump_providers_.begin();
  for (; mdp_iter != dump_providers_.end(); ++mdp_iter) {
    if ((*mdp_iter)->dump_provider == mdp)
      break;
  }

  if (mdp_iter == dump_providers_.end())
    return;  // Not registered / already unregistered.

  if (take_mdp_ownership_and_delete_async) {
    // The MDP will be deleted whenever the MDPInfo struct will, that is either:
    // - At the end of this function, if no dump is in progress.
    // - Either in SetupNextMemoryDump() or InvokeOnMemoryDump() when MDPInfo is
    //   removed from |pending_dump_providers|.
    DCHECK(!(*mdp_iter)->owned_dump_provider);
    (*mdp_iter)->owned_dump_provider = std::move(owned_mdp);
  } else if (subtle::NoBarrier_Load(&memory_tracing_enabled_)) {
    // If you hit this DCHECK, your dump provider has a bug.
    // Unregistration of a MemoryDumpProvider is safe only if:
    // - The MDP has specified a sequenced task runner affinity AND the
    //   unregistration happens on the same task runner. So that the MDP cannot
    //   unregister and be in the middle of a OnMemoryDump() at the same time.
    // - The MDP has NOT specified a task runner affinity and its ownership is
    //   transferred via UnregisterAndDeleteDumpProviderSoon().
    // In all the other cases, it is not possible to guarantee that the
    // unregistration will not race with OnMemoryDump() calls.
    DCHECK((*mdp_iter)->task_runner &&
           (*mdp_iter)->task_runner->RunsTasksOnCurrentThread())
        << "MemoryDumpProvider \"" << (*mdp_iter)->name << "\" attempted to "
        << "unregister itself in a racy way. Please file a crbug.";
  }

  // The MDPInfo instance can still be referenced by the
  // |ProcessMemoryDumpAsyncState.pending_dump_providers|. For this reason
  // the MDPInfo is flagged as disabled. It will cause InvokeOnMemoryDump()
  // to just skip it, without actually invoking the |mdp|, which might be
  // destroyed by the caller soon after this method returns.
  (*mdp_iter)->disabled = true;
  dump_providers_.erase(mdp_iter);
}

void MemoryDumpManager::RequestGlobalDump(
    MemoryDumpType dump_type,
    MemoryDumpLevelOfDetail level_of_detail,
    const MemoryDumpCallback& callback) {
  // Bail out immediately if tracing is not enabled at all or if the dump mode
  // is not allowed.
  if (!UNLIKELY(subtle::NoBarrier_Load(&memory_tracing_enabled_)) ||
      !IsDumpModeAllowed(level_of_detail)) {
    VLOG(1) << kLogPrefix << " failed because " << kTraceCategory
            << " tracing category is not enabled or the requested dump mode is "
               "not allowed by trace config.";
    if (!callback.is_null())
      callback.Run(0u /* guid */, false /* success */);
    return;
  }

  const uint64_t guid =
      TraceLog::GetInstance()->MangleEventId(g_next_guid.GetNext());

  // Creates an async event to keep track of the global dump evolution.
  // The |wrapped_callback| will generate the ASYNC_END event and then invoke
  // the real |callback| provided by the caller.
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(kTraceCategory, "GlobalMemoryDump",
                                    TRACE_ID_MANGLE(guid));
  MemoryDumpCallback wrapped_callback = Bind(&OnGlobalDumpDone, callback);

  // Technically there is no need to grab the |lock_| here as the delegate is
  // long-lived and can only be set by Initialize(), which is locked and
  // necessarily happens before memory_tracing_enabled_ == true.
  // Not taking the |lock_|, though, is lakely make TSan barf and, at this point
  // (memory-infra is enabled) we're not in the fast-path anymore.
  MemoryDumpManagerDelegate* delegate;
  {
    AutoLock lock(lock_);
    delegate = delegate_;
  }

  // The delegate will coordinate the IPC broadcast and at some point invoke
  // CreateProcessDump() to get a dump for the current process.
  MemoryDumpRequestArgs args = {guid, dump_type, level_of_detail};
  delegate->RequestGlobalMemoryDump(args, wrapped_callback);
}

void MemoryDumpManager::RequestGlobalDump(
    MemoryDumpType dump_type,
    MemoryDumpLevelOfDetail level_of_detail) {
  RequestGlobalDump(dump_type, level_of_detail, MemoryDumpCallback());
}

void MemoryDumpManager::CreateProcessDump(const MemoryDumpRequestArgs& args,
                                          const MemoryDumpCallback& callback) {
  TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(kTraceCategory, "ProcessMemoryDump",
                                    TRACE_ID_MANGLE(args.dump_guid));

  // If argument filter is enabled then only background mode dumps should be
  // allowed. In case the trace config passed for background tracing session
  // missed the allowed modes argument, it crashes here instead of creating
  // unexpected dumps.
  if (TraceLog::GetInstance()
          ->GetCurrentTraceConfig()
          .IsArgumentFilterEnabled()) {
    CHECK_EQ(MemoryDumpLevelOfDetail::BACKGROUND, args.level_of_detail);
  }

  std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state;
  {
    AutoLock lock(lock_);

    // |dump_thread_| can be nullptr is tracing was disabled before reaching
    // here. SetupNextMemoryDump() is robust enough to tolerate it and will
    // NACK the dump.
    pmd_async_state.reset(new ProcessMemoryDumpAsyncState(
        args, dump_providers_, session_state_, callback,
        dump_thread_ ? dump_thread_->task_runner() : nullptr));

    // Safety check to prevent reaching here without calling RequestGlobalDump,
    // with disallowed modes. If |session_state_| is null then tracing is
    // disabled.
    CHECK(!session_state_ ||
          session_state_->memory_dump_config().allowed_dump_modes.count(
              args.level_of_detail));
  }

  TRACE_EVENT_WITH_FLOW0(kTraceCategory, "MemoryDumpManager::CreateProcessDump",
                         TRACE_ID_MANGLE(args.dump_guid),
                         TRACE_EVENT_FLAG_FLOW_OUT);

  // Start the process dump. This involves task runner hops as specified by the
  // MemoryDumpProvider(s) in RegisterDumpProvider()).
  SetupNextMemoryDump(std::move(pmd_async_state));
}

// PostTask InvokeOnMemoryDump() to the dump provider's sequenced task runner. A
// PostTask is always required for a generic SequencedTaskRunner to ensure that
// no other task is running on it concurrently. SetupNextMemoryDump() and
// InvokeOnMemoryDump() are called alternatively which linearizes the dump
// provider's OnMemoryDump invocations.
// At most one of either SetupNextMemoryDump() or InvokeOnMemoryDump() can be
// active at any time for a given PMD, regardless of status of the |lock_|.
// |lock_| is used in these functions purely to ensure consistency w.r.t.
// (un)registrations of |dump_providers_|.
void MemoryDumpManager::SetupNextMemoryDump(
    std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state) {
  HEAP_PROFILER_SCOPED_IGNORE;
  // Initalizes the ThreadLocalEventBuffer to guarantee that the TRACE_EVENTs
  // in the PostTask below don't end up registering their own dump providers
  // (for discounting trace memory overhead) while holding the |lock_|.
  TraceLog::GetInstance()->InitializeThreadLocalEventBufferIfSupported();

  // |dump_thread_| might be destroyed before getting this point.
  // It means that tracing was disabled right before starting this dump.
  // Anyway either tracing is stopped or this was the last hop, create a trace
  // event, add it to the trace and finalize process dump invoking the callback.
  if (!pmd_async_state->dump_thread_task_runner.get()) {
    if (pmd_async_state->pending_dump_providers.empty()) {
      VLOG(1) << kLogPrefix << " failed because dump thread was destroyed"
              << " before finalizing the dump";
    } else {
      VLOG(1) << kLogPrefix << " failed because dump thread was destroyed"
              << " before dumping "
              << pmd_async_state->pending_dump_providers.back().get()->name;
    }
    pmd_async_state->dump_successful = false;
    pmd_async_state->pending_dump_providers.clear();
  }
  if (pmd_async_state->pending_dump_providers.empty())
    return FinalizeDumpAndAddToTrace(std::move(pmd_async_state));

  // Read MemoryDumpProviderInfo thread safety considerations in
  // memory_dump_manager.h when accessing |mdpinfo| fields.
  MemoryDumpProviderInfo* mdpinfo =
      pmd_async_state->pending_dump_providers.back().get();

  // If we are in background tracing, we should invoke only the whitelisted
  // providers. Ignore other providers and continue.
  if (pmd_async_state->req_args.level_of_detail ==
          MemoryDumpLevelOfDetail::BACKGROUND &&
      !mdpinfo->whitelisted_for_background_mode) {
    pmd_async_state->pending_dump_providers.pop_back();
    return SetupNextMemoryDump(std::move(pmd_async_state));
  }

  // If the dump provider did not specify a task runner affinity, dump on
  // |dump_thread_| which is already checked above for presence.
  SequencedTaskRunner* task_runner = mdpinfo->task_runner.get();
  if (!task_runner) {
    DCHECK(mdpinfo->options.dumps_on_single_thread_task_runner);
    task_runner = pmd_async_state->dump_thread_task_runner.get();
    DCHECK(task_runner);
  }

  if (mdpinfo->options.dumps_on_single_thread_task_runner &&
      task_runner->RunsTasksOnCurrentThread()) {
    // If |dumps_on_single_thread_task_runner| is true then no PostTask is
    // required if we are on the right thread.
    return InvokeOnMemoryDump(pmd_async_state.release());
  }

  bool did_post_task = task_runner->PostTask(
      FROM_HERE, Bind(&MemoryDumpManager::InvokeOnMemoryDump, Unretained(this),
                      Unretained(pmd_async_state.get())));

  if (did_post_task) {
    // Ownership is tranferred to InvokeOnMemoryDump().
    ignore_result(pmd_async_state.release());
    return;
  }

  // PostTask usually fails only if the process or thread is shut down. So, the
  // dump provider is disabled here. But, don't disable unbound dump providers.
  // The utility thread is normally shutdown when disabling the trace and
  // getting here in this case is expected.
  if (mdpinfo->task_runner) {
    LOG(ERROR) << "Disabling MemoryDumpProvider \"" << mdpinfo->name
               << "\". Failed to post task on the task runner provided.";

    // A locked access is required to R/W |disabled| (for the
    // UnregisterAndDeleteDumpProviderSoon() case).
    AutoLock lock(lock_);
    mdpinfo->disabled = true;
  }

  // PostTask failed. Ignore the dump provider and continue.
  pmd_async_state->pending_dump_providers.pop_back();
  SetupNextMemoryDump(std::move(pmd_async_state));
}

// This function is called on the right task runner for current MDP. It is
// either the task runner specified by MDP or |dump_thread_task_runner| if the
// MDP did not specify task runner. Invokes the dump provider's OnMemoryDump()
// (unless disabled).
void MemoryDumpManager::InvokeOnMemoryDump(
    ProcessMemoryDumpAsyncState* owned_pmd_async_state) {
  HEAP_PROFILER_SCOPED_IGNORE;
  // In theory |owned_pmd_async_state| should be a scoped_ptr. The only reason
  // why it isn't is because of the corner case logic of |did_post_task|
  // above, which needs to take back the ownership of the |pmd_async_state| when
  // the PostTask() fails.
  // Unfortunately, PostTask() destroys the scoped_ptr arguments upon failure
  // to prevent accidental leaks. Using a scoped_ptr would prevent us to to
  // skip the hop and move on. Hence the manual naked -> scoped ptr juggling.
  auto pmd_async_state = WrapUnique(owned_pmd_async_state);
  owned_pmd_async_state = nullptr;

  // Read MemoryDumpProviderInfo thread safety considerations in
  // memory_dump_manager.h when accessing |mdpinfo| fields.
  MemoryDumpProviderInfo* mdpinfo =
      pmd_async_state->pending_dump_providers.back().get();

  DCHECK(!mdpinfo->task_runner ||
         mdpinfo->task_runner->RunsTasksOnCurrentThread());

  bool should_dump;
  {
    // A locked access is required to R/W |disabled| (for the
    // UnregisterAndDeleteDumpProviderSoon() case).
    AutoLock lock(lock_);

    // Unregister the dump provider if it failed too many times consecutively.
    if (!mdpinfo->disabled &&
        mdpinfo->consecutive_failures >= kMaxConsecutiveFailuresCount) {
      mdpinfo->disabled = true;
      LOG(ERROR) << "Disabling MemoryDumpProvider \"" << mdpinfo->name
                 << "\". Dump failed multiple times consecutively.";
    }
    should_dump = !mdpinfo->disabled;
  }  // AutoLock lock(lock_);

  if (should_dump) {
    // Invoke the dump provider.
    TRACE_EVENT_WITH_FLOW1(kTraceCategory,
                           "MemoryDumpManager::InvokeOnMemoryDump",
                           TRACE_ID_MANGLE(pmd_async_state->req_args.dump_guid),
                           TRACE_EVENT_FLAG_FLOW_IN | TRACE_EVENT_FLAG_FLOW_OUT,
                           "dump_provider.name", mdpinfo->name);

    // Pid of the target process being dumped. Often kNullProcessId (= current
    // process), non-zero when the coordinator process creates dumps on behalf
    // of child processes (see crbug.com/461788).
    ProcessId target_pid = mdpinfo->options.target_pid;
    MemoryDumpArgs args = {pmd_async_state->req_args.level_of_detail};
    ProcessMemoryDump* pmd =
        pmd_async_state->GetOrCreateMemoryDumpContainerForProcess(target_pid,
                                                                  args);
    bool dump_successful = mdpinfo->dump_provider->OnMemoryDump(args, pmd);
    mdpinfo->consecutive_failures =
        dump_successful ? 0 : mdpinfo->consecutive_failures + 1;
  }

  pmd_async_state->pending_dump_providers.pop_back();
  SetupNextMemoryDump(std::move(pmd_async_state));
}

// static
void MemoryDumpManager::FinalizeDumpAndAddToTrace(
    std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state) {
  HEAP_PROFILER_SCOPED_IGNORE;
  DCHECK(pmd_async_state->pending_dump_providers.empty());
  const uint64_t dump_guid = pmd_async_state->req_args.dump_guid;
  if (!pmd_async_state->callback_task_runner->BelongsToCurrentThread()) {
    scoped_refptr<SingleThreadTaskRunner> callback_task_runner =
        pmd_async_state->callback_task_runner;
    callback_task_runner->PostTask(
        FROM_HERE, Bind(&MemoryDumpManager::FinalizeDumpAndAddToTrace,
                        Passed(&pmd_async_state)));
    return;
  }

  TRACE_EVENT_WITH_FLOW0(kTraceCategory,
                         "MemoryDumpManager::FinalizeDumpAndAddToTrace",
                         TRACE_ID_MANGLE(dump_guid), TRACE_EVENT_FLAG_FLOW_IN);

  for (const auto& kv : pmd_async_state->process_dumps) {
    ProcessId pid = kv.first;  // kNullProcessId for the current process.
    ProcessMemoryDump* process_memory_dump = kv.second.get();
    std::unique_ptr<TracedValue> traced_value(new TracedValue);
    process_memory_dump->AsValueInto(traced_value.get());
    traced_value->SetString("level_of_detail",
                            MemoryDumpLevelOfDetailToString(
                                pmd_async_state->req_args.level_of_detail));
    const char* const event_name =
        MemoryDumpTypeToString(pmd_async_state->req_args.dump_type);

    std::unique_ptr<ConvertableToTraceFormat> event_value(
        std::move(traced_value));
    TRACE_EVENT_API_ADD_TRACE_EVENT_WITH_PROCESS_ID(
        TRACE_EVENT_PHASE_MEMORY_DUMP,
        TraceLog::GetCategoryGroupEnabled(kTraceCategory), event_name,
        trace_event_internal::kGlobalScope, dump_guid, pid,
        kTraceEventNumArgs, kTraceEventArgNames,
        kTraceEventArgTypes, nullptr /* arg_values */, &event_value,
        TRACE_EVENT_FLAG_HAS_ID);
  }

  bool tracing_still_enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(kTraceCategory, &tracing_still_enabled);
  if (!tracing_still_enabled) {
    pmd_async_state->dump_successful = false;
    VLOG(1) << kLogPrefix << " failed because tracing was disabled before"
            << " the dump was completed";
  }

  if (!pmd_async_state->callback.is_null()) {
    pmd_async_state->callback.Run(dump_guid, pmd_async_state->dump_successful);
    pmd_async_state->callback.Reset();
  }

  TRACE_EVENT_NESTABLE_ASYNC_END0(kTraceCategory, "ProcessMemoryDump",
                                  TRACE_ID_MANGLE(dump_guid));
}

void MemoryDumpManager::OnTraceLogEnabled() {
  bool enabled;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED(kTraceCategory, &enabled);
  if (!enabled)
    return;

  // Initialize the TraceLog for the current thread. This is to avoid that the
  // TraceLog memory dump provider is registered lazily in the PostTask() below
  // while the |lock_| is taken;
  TraceLog::GetInstance()->InitializeThreadLocalEventBufferIfSupported();

  // Spin-up the thread used to invoke unbound dump providers.
  std::unique_ptr<Thread> dump_thread(new Thread("MemoryInfra"));
  if (!dump_thread->Start()) {
    LOG(ERROR) << "Failed to start the memory-infra thread for tracing";
    return;
  }

  const TraceConfig trace_config =
      TraceLog::GetInstance()->GetCurrentTraceConfig();
  scoped_refptr<MemoryDumpSessionState> session_state =
      new MemoryDumpSessionState;
  session_state->SetMemoryDumpConfig(trace_config.memory_dump_config());
  if (heap_profiling_enabled_) {
    // If heap profiling is enabled, the stack frame deduplicator and type name
    // deduplicator will be in use. Add a metadata events to write the frames
    // and type IDs.
    session_state->SetStackFrameDeduplicator(
        WrapUnique(new StackFrameDeduplicator));

    session_state->SetTypeNameDeduplicator(
        WrapUnique(new TypeNameDeduplicator));

    TRACE_EVENT_API_ADD_METADATA_EVENT(
        TraceLog::GetCategoryGroupEnabled("__metadata"), "stackFrames",
        "stackFrames",
        MakeUnique<SessionStateConvertableProxy<StackFrameDeduplicator>>(
            session_state, &MemoryDumpSessionState::stack_frame_deduplicator));

    TRACE_EVENT_API_ADD_METADATA_EVENT(
        TraceLog::GetCategoryGroupEnabled("__metadata"), "typeNames",
        "typeNames",
        MakeUnique<SessionStateConvertableProxy<TypeNameDeduplicator>>(
            session_state, &MemoryDumpSessionState::type_name_deduplicator));
  }

  {
    AutoLock lock(lock_);

    DCHECK(delegate_);  // At this point we must have a delegate.
    session_state_ = session_state;

    DCHECK(!dump_thread_);
    dump_thread_ = std::move(dump_thread);

    subtle::NoBarrier_Store(&memory_tracing_enabled_, 1);

    // TODO(primiano): This is a temporary hack to disable periodic memory dumps
    // when running memory benchmarks until telemetry uses TraceConfig to
    // enable/disable periodic dumps. See crbug.com/529184 .
    if (!is_coordinator_ ||
        CommandLine::ForCurrentProcess()->HasSwitch(
            "enable-memory-benchmarking")) {
      return;
    }
  }

  // Enable periodic dumps if necessary.
  periodic_dump_timer_.Start(trace_config.memory_dump_config().triggers);
}

void MemoryDumpManager::OnTraceLogDisabled() {
  // There might be a memory dump in progress while this happens. Therefore,
  // ensure that the MDM state which depends on the tracing enabled / disabled
  // state is always accessed by the dumping methods holding the |lock_|.
  subtle::NoBarrier_Store(&memory_tracing_enabled_, 0);
  std::unique_ptr<Thread> dump_thread;
  {
    AutoLock lock(lock_);
    dump_thread = std::move(dump_thread_);
    session_state_ = nullptr;
  }

  // Thread stops are blocking and must be performed outside of the |lock_|
  // or will deadlock (e.g., if SetupNextMemoryDump() tries to acquire it).
  periodic_dump_timer_.Stop();
  if (dump_thread)
    dump_thread->Stop();
}

bool MemoryDumpManager::IsDumpModeAllowed(MemoryDumpLevelOfDetail dump_mode) {
  AutoLock lock(lock_);
  if (!session_state_)
    return false;
  return session_state_->memory_dump_config().allowed_dump_modes.count(
             dump_mode) != 0;
}

uint64_t MemoryDumpManager::GetTracingProcessId() const {
  return delegate_->GetTracingProcessId();
}

MemoryDumpManager::MemoryDumpProviderInfo::MemoryDumpProviderInfo(
    MemoryDumpProvider* dump_provider,
    const char* name,
    scoped_refptr<SequencedTaskRunner> task_runner,
    const MemoryDumpProvider::Options& options,
    bool whitelisted_for_background_mode)
    : dump_provider(dump_provider),
      name(name),
      task_runner(std::move(task_runner)),
      options(options),
      consecutive_failures(0),
      disabled(false),
      whitelisted_for_background_mode(whitelisted_for_background_mode) {}

MemoryDumpManager::MemoryDumpProviderInfo::~MemoryDumpProviderInfo() {}

bool MemoryDumpManager::MemoryDumpProviderInfo::Comparator::operator()(
    const scoped_refptr<MemoryDumpManager::MemoryDumpProviderInfo>& a,
    const scoped_refptr<MemoryDumpManager::MemoryDumpProviderInfo>& b) const {
  if (!a || !b)
    return a.get() < b.get();
  // Ensure that unbound providers (task_runner == nullptr) always run last.
  // Rationale: some unbound dump providers are known to be slow, keep them last
  // to avoid skewing timings of the other dump providers.
  return std::tie(a->task_runner, a->dump_provider) >
         std::tie(b->task_runner, b->dump_provider);
}

MemoryDumpManager::ProcessMemoryDumpAsyncState::ProcessMemoryDumpAsyncState(
    MemoryDumpRequestArgs req_args,
    const MemoryDumpProviderInfo::OrderedSet& dump_providers,
    scoped_refptr<MemoryDumpSessionState> session_state,
    MemoryDumpCallback callback,
    scoped_refptr<SingleThreadTaskRunner> dump_thread_task_runner)
    : req_args(req_args),
      session_state(std::move(session_state)),
      callback(callback),
      dump_successful(true),
      callback_task_runner(ThreadTaskRunnerHandle::Get()),
      dump_thread_task_runner(std::move(dump_thread_task_runner)) {
  pending_dump_providers.reserve(dump_providers.size());
  pending_dump_providers.assign(dump_providers.rbegin(), dump_providers.rend());
}

MemoryDumpManager::ProcessMemoryDumpAsyncState::~ProcessMemoryDumpAsyncState() {
}

ProcessMemoryDump* MemoryDumpManager::ProcessMemoryDumpAsyncState::
    GetOrCreateMemoryDumpContainerForProcess(ProcessId pid,
                                             const MemoryDumpArgs& dump_args) {
  auto iter = process_dumps.find(pid);
  if (iter == process_dumps.end()) {
    std::unique_ptr<ProcessMemoryDump> new_pmd(
        new ProcessMemoryDump(session_state, dump_args));
    iter = process_dumps.insert(std::make_pair(pid, std::move(new_pmd))).first;
  }
  return iter->second.get();
}

MemoryDumpManager::PeriodicGlobalDumpTimer::PeriodicGlobalDumpTimer() {}

MemoryDumpManager::PeriodicGlobalDumpTimer::~PeriodicGlobalDumpTimer() {
  Stop();
}

void MemoryDumpManager::PeriodicGlobalDumpTimer::Start(
    const std::vector<TraceConfig::MemoryDumpConfig::Trigger>& triggers_list) {
  if (triggers_list.empty())
    return;

  // At the moment the periodic support is limited to at most one periodic
  // trigger per dump mode. All intervals should be an integer multiple of the
  // smallest interval specified.
  periodic_dumps_count_ = 0;
  uint32_t min_timer_period_ms = std::numeric_limits<uint32_t>::max();
  uint32_t light_dump_period_ms = 0;
  uint32_t heavy_dump_period_ms = 0;
  DCHECK_LE(triggers_list.size(), 3u);
  auto* mdm = MemoryDumpManager::GetInstance();
  for (const TraceConfig::MemoryDumpConfig::Trigger& config : triggers_list) {
    DCHECK_NE(0u, config.periodic_interval_ms);
    switch (config.level_of_detail) {
      case MemoryDumpLevelOfDetail::BACKGROUND:
        DCHECK(mdm->IsDumpModeAllowed(MemoryDumpLevelOfDetail::BACKGROUND));
        break;
      case MemoryDumpLevelOfDetail::LIGHT:
        DCHECK_EQ(0u, light_dump_period_ms);
        DCHECK(mdm->IsDumpModeAllowed(MemoryDumpLevelOfDetail::LIGHT));
        light_dump_period_ms = config.periodic_interval_ms;
        break;
      case MemoryDumpLevelOfDetail::DETAILED:
        DCHECK_EQ(0u, heavy_dump_period_ms);
        DCHECK(mdm->IsDumpModeAllowed(MemoryDumpLevelOfDetail::DETAILED));
        heavy_dump_period_ms = config.periodic_interval_ms;
        break;
    }
    min_timer_period_ms =
        std::min(min_timer_period_ms, config.periodic_interval_ms);
  }

  DCHECK_EQ(0u, light_dump_period_ms % min_timer_period_ms);
  light_dump_rate_ = light_dump_period_ms / min_timer_period_ms;
  DCHECK_EQ(0u, heavy_dump_period_ms % min_timer_period_ms);
  heavy_dump_rate_ = heavy_dump_period_ms / min_timer_period_ms;

  timer_.Start(FROM_HERE, TimeDelta::FromMilliseconds(min_timer_period_ms),
               base::Bind(&PeriodicGlobalDumpTimer::RequestPeriodicGlobalDump,
                          base::Unretained(this)));
}

void MemoryDumpManager::PeriodicGlobalDumpTimer::Stop() {
  if (IsRunning()) {
    timer_.Stop();
  }
}

bool MemoryDumpManager::PeriodicGlobalDumpTimer::IsRunning() {
  return timer_.IsRunning();
}

void MemoryDumpManager::PeriodicGlobalDumpTimer::RequestPeriodicGlobalDump() {
  MemoryDumpLevelOfDetail level_of_detail = MemoryDumpLevelOfDetail::BACKGROUND;
  if (light_dump_rate_ > 0 && periodic_dumps_count_ % light_dump_rate_ == 0)
    level_of_detail = MemoryDumpLevelOfDetail::LIGHT;
  if (heavy_dump_rate_ > 0 && periodic_dumps_count_ % heavy_dump_rate_ == 0)
    level_of_detail = MemoryDumpLevelOfDetail::DETAILED;
  ++periodic_dumps_count_;

  MemoryDumpManager::GetInstance()->RequestGlobalDump(
      MemoryDumpType::PERIODIC_INTERVAL, level_of_detail);
}

}  // namespace trace_event
}  // namespace base
