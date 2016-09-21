// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_
#define BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <vector>

#include "base/atomicops.h"
#include "base/containers/hash_tables.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/singleton.h"
#include "base/synchronization/lock.h"
#include "base/timer/timer.h"
#include "base/trace_event/memory_dump_request_args.h"
#include "base/trace_event/process_memory_dump.h"
#include "base/trace_event/trace_event.h"

namespace base {

class SingleThreadTaskRunner;
class Thread;

namespace trace_event {

class MemoryDumpManagerDelegate;
class MemoryDumpProvider;
class MemoryDumpSessionState;

// This is the interface exposed to the rest of the codebase to deal with
// memory tracing. The main entry point for clients is represented by
// RequestDumpPoint(). The extension by Un(RegisterDumpProvider).
class BASE_EXPORT MemoryDumpManager : public TraceLog::EnabledStateObserver {
 public:
  static const char* const kTraceCategory;
  static const char* const kLogPrefix;

  // This value is returned as the tracing id of the child processes by
  // GetTracingProcessId() when tracing is not enabled.
  static const uint64_t kInvalidTracingProcessId;

  static MemoryDumpManager* GetInstance();

  // Invoked once per process to listen to trace begin / end events.
  // Initialization can happen after (Un)RegisterMemoryDumpProvider() calls
  // and the MemoryDumpManager guarantees to support this.
  // On the other side, the MemoryDumpManager will not be fully operational
  // (i.e. will NACK any RequestGlobalMemoryDump()) until initialized.
  // Arguments:
  //  is_coordinator: if true this MemoryDumpManager instance will act as a
  //      coordinator and schedule periodic dumps (if enabled via TraceConfig);
  //      false when the MemoryDumpManager is initialized in a slave process.
  //  delegate: inversion-of-control interface for embedder-specific behaviors
  //      (multiprocess handshaking). See the lifetime and thread-safety
  //      requirements in the |MemoryDumpManagerDelegate| docstring.
  void Initialize(MemoryDumpManagerDelegate* delegate, bool is_coordinator);

  // (Un)Registers a MemoryDumpProvider instance.
  // Args:
  //  - mdp: the MemoryDumpProvider instance to be registered. MemoryDumpManager
  //      does NOT take memory ownership of |mdp|, which is expected to either
  //      be a singleton or unregister itself.
  //  - name: a friendly name (duplicates allowed). Used for debugging and
  //      run-time profiling of memory-infra internals. Must be a long-lived
  //      C string.
  //  - task_runner: either a SingleThreadTaskRunner or SequencedTaskRunner. All
  //      the calls to |mdp| will be run on the given |task_runner|. If passed
  //      null |mdp| should be able to handle calls on arbitrary threads.
  //  - options: extra optional arguments. See memory_dump_provider.h.
  void RegisterDumpProvider(MemoryDumpProvider* mdp,
                            const char* name,
                            scoped_refptr<SingleThreadTaskRunner> task_runner);
  void RegisterDumpProvider(MemoryDumpProvider* mdp,
                            const char* name,
                            scoped_refptr<SingleThreadTaskRunner> task_runner,
                            MemoryDumpProvider::Options options);
  void RegisterDumpProviderWithSequencedTaskRunner(
      MemoryDumpProvider* mdp,
      const char* name,
      scoped_refptr<SequencedTaskRunner> task_runner,
      MemoryDumpProvider::Options options);
  void UnregisterDumpProvider(MemoryDumpProvider* mdp);

  // Unregisters an unbound dump provider and takes care about its deletion
  // asynchronously. Can be used only for for dump providers with no
  // task-runner affinity.
  // This method takes ownership of the dump provider and guarantees that:
  //  - The |mdp| will be deleted at some point in the near future.
  //  - Its deletion will not happen concurrently with the OnMemoryDump() call.
  // Note that OnMemoryDump() calls can still happen after this method returns.
  void UnregisterAndDeleteDumpProviderSoon(
      std::unique_ptr<MemoryDumpProvider> mdp);

  // Requests a memory dump. The dump might happen or not depending on the
  // filters and categories specified when enabling tracing.
  // The optional |callback| is executed asynchronously, on an arbitrary thread,
  // to notify about the completion of the global dump (i.e. after all the
  // processes have dumped) and its success (true iff all the dumps were
  // successful).
  void RequestGlobalDump(MemoryDumpType dump_type,
                         MemoryDumpLevelOfDetail level_of_detail,
                         const MemoryDumpCallback& callback);

  // Same as above (still asynchronous), but without callback.
  void RequestGlobalDump(MemoryDumpType dump_type,
                         MemoryDumpLevelOfDetail level_of_detail);

  // TraceLog::EnabledStateObserver implementation.
  void OnTraceLogEnabled() override;
  void OnTraceLogDisabled() override;

  // Returns true if the dump mode is allowed for current tracing session.
  bool IsDumpModeAllowed(MemoryDumpLevelOfDetail dump_mode);

  // Returns the MemoryDumpSessionState object, which is shared by all the
  // ProcessMemoryDump and MemoryAllocatorDump instances through all the tracing
  // session lifetime.
  const scoped_refptr<MemoryDumpSessionState>& session_state_for_testing()
      const {
    return session_state_;
  }

  // Returns a unique id for identifying the processes. The id can be
  // retrieved by child processes only when tracing is enabled. This is
  // intended to express cross-process sharing of memory dumps on the
  // child-process side, without having to know its own child process id.
  uint64_t GetTracingProcessId() const;

  // Returns the name for a the allocated_objects dump. Use this to declare
  // suballocator dumps from other dump providers.
  // It will return nullptr if there is no dump provider for the system
  // allocator registered (which is currently the case for Mac OS).
  const char* system_allocator_pool_name() const {
    return kSystemAllocatorPoolName;
  };

  // When set to true, calling |RegisterMemoryDumpProvider| is a no-op.
  void set_dumper_registrations_ignored_for_testing(bool ignored) {
    dumper_registrations_ignored_for_testing_ = ignored;
  }

 private:
  friend std::default_delete<MemoryDumpManager>;  // For the testing instance.
  friend struct DefaultSingletonTraits<MemoryDumpManager>;
  friend class MemoryDumpManagerDelegate;
  friend class MemoryDumpManagerTest;

  // Descriptor used to hold information about registered MDPs.
  // Some important considerations about lifetime of this object:
  // - In nominal conditions, all the MemoryDumpProviderInfo instances live in
  //   the |dump_providers_| collection (% unregistration while dumping).
  // - Upon each dump they (actually their scoped_refptr-s) are copied into
  //   the ProcessMemoryDumpAsyncState. This is to allow removal (see below).
  // - When the MDP.OnMemoryDump() is invoked, the corresponding MDPInfo copy
  //   inside ProcessMemoryDumpAsyncState is removed.
  // - In most cases, the MDPInfo is destroyed within UnregisterDumpProvider().
  // - If UnregisterDumpProvider() is called while a dump is in progress, the
  //   MDPInfo is destroyed in SetupNextMemoryDump() or InvokeOnMemoryDump(),
  //   when the copy inside ProcessMemoryDumpAsyncState is erase()-d.
  // - The non-const fields of MemoryDumpProviderInfo are safe to access only
  //   on tasks running in the |task_runner|, unless the thread has been
  //   destroyed.
  struct MemoryDumpProviderInfo
      : public RefCountedThreadSafe<MemoryDumpProviderInfo> {
    // Define a total order based on the |task_runner| affinity, so that MDPs
    // belonging to the same SequencedTaskRunner are adjacent in the set.
    struct Comparator {
      bool operator()(const scoped_refptr<MemoryDumpProviderInfo>& a,
                      const scoped_refptr<MemoryDumpProviderInfo>& b) const;
    };
    using OrderedSet =
        std::set<scoped_refptr<MemoryDumpProviderInfo>, Comparator>;

    MemoryDumpProviderInfo(MemoryDumpProvider* dump_provider,
                           const char* name,
                           scoped_refptr<SequencedTaskRunner> task_runner,
                           const MemoryDumpProvider::Options& options,
                           bool whitelisted_for_background_mode);

    MemoryDumpProvider* const dump_provider;

    // Used to transfer ownership for UnregisterAndDeleteDumpProviderSoon().
    // nullptr in all other cases.
    std::unique_ptr<MemoryDumpProvider> owned_dump_provider;

    // Human readable name, for debugging and testing. Not necessarily unique.
    const char* const name;

    // The task runner affinity. Can be nullptr, in which case the dump provider
    // will be invoked on |dump_thread_|.
    const scoped_refptr<SequencedTaskRunner> task_runner;

    // The |options| arg passed to RegisterDumpProvider().
    const MemoryDumpProvider::Options options;

    // For fail-safe logic (auto-disable failing MDPs).
    int consecutive_failures;

    // Flagged either by the auto-disable logic or during unregistration.
    bool disabled;

    // True if the dump provider is whitelisted for background mode.
    const bool whitelisted_for_background_mode;

   private:
    friend class base::RefCountedThreadSafe<MemoryDumpProviderInfo>;
    ~MemoryDumpProviderInfo();

    DISALLOW_COPY_AND_ASSIGN(MemoryDumpProviderInfo);
  };

  // Holds the state of a process memory dump that needs to be carried over
  // across task runners in order to fulfil an asynchronous CreateProcessDump()
  // request. At any time exactly one task runner owns a
  // ProcessMemoryDumpAsyncState.
  struct ProcessMemoryDumpAsyncState {
    ProcessMemoryDumpAsyncState(
        MemoryDumpRequestArgs req_args,
        const MemoryDumpProviderInfo::OrderedSet& dump_providers,
        scoped_refptr<MemoryDumpSessionState> session_state,
        MemoryDumpCallback callback,
        scoped_refptr<SingleThreadTaskRunner> dump_thread_task_runner);
    ~ProcessMemoryDumpAsyncState();

    // Gets or creates the memory dump container for the given target process.
    ProcessMemoryDump* GetOrCreateMemoryDumpContainerForProcess(
        ProcessId pid,
        const MemoryDumpArgs& dump_args);

    // A map of ProcessId -> ProcessMemoryDump, one for each target process
    // being dumped from the current process. Typically each process dumps only
    // for itself, unless dump providers specify a different |target_process| in
    // MemoryDumpProvider::Options.
    std::map<ProcessId, std::unique_ptr<ProcessMemoryDump>> process_dumps;

    // The arguments passed to the initial CreateProcessDump() request.
    const MemoryDumpRequestArgs req_args;

    // An ordered sequence of dump providers that have to be invoked to complete
    // the dump. This is a copy of |dump_providers_| at the beginning of a dump
    // and becomes empty at the end, when all dump providers have been invoked.
    std::vector<scoped_refptr<MemoryDumpProviderInfo>> pending_dump_providers;

    // The trace-global session state.
    scoped_refptr<MemoryDumpSessionState> session_state;

    // Callback passed to the initial call to CreateProcessDump().
    MemoryDumpCallback callback;

    // The |success| field that will be passed as argument to the |callback|.
    bool dump_successful;

    // The thread on which FinalizeDumpAndAddToTrace() (and hence |callback|)
    // should be invoked. This is the thread on which the initial
    // CreateProcessDump() request was called.
    const scoped_refptr<SingleThreadTaskRunner> callback_task_runner;

    // The thread on which unbound dump providers should be invoked.
    // This is essentially |dump_thread_|.task_runner() but needs to be kept
    // as a separate variable as it needs to be accessed by arbitrary dumpers'
    // threads outside of the lock_ to avoid races when disabling tracing.
    // It is immutable for all the duration of a tracing session.
    const scoped_refptr<SingleThreadTaskRunner> dump_thread_task_runner;

   private:
    DISALLOW_COPY_AND_ASSIGN(ProcessMemoryDumpAsyncState);
  };

  // Sets up periodic memory dump timers to start global dump requests based on
  // the dump triggers from trace config.
  class BASE_EXPORT PeriodicGlobalDumpTimer {
   public:
    PeriodicGlobalDumpTimer();
    ~PeriodicGlobalDumpTimer();

    void Start(const std::vector<TraceConfig::MemoryDumpConfig::Trigger>&
                   triggers_list);
    void Stop();

    bool IsRunning();

   private:
    // Periodically called by the timer.
    void RequestPeriodicGlobalDump();

    RepeatingTimer timer_;
    uint32_t periodic_dumps_count_;
    uint32_t light_dump_rate_;
    uint32_t heavy_dump_rate_;

    DISALLOW_COPY_AND_ASSIGN(PeriodicGlobalDumpTimer);
  };

  static const int kMaxConsecutiveFailuresCount;
  static const char* const kSystemAllocatorPoolName;

  MemoryDumpManager();
  ~MemoryDumpManager() override;

  static void SetInstanceForTesting(MemoryDumpManager* instance);
  static void FinalizeDumpAndAddToTrace(
      std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state);

  // Enable heap profiling if kEnableHeapProfiling is specified.
  void EnableHeapProfilingIfNeeded();

  // Internal, used only by MemoryDumpManagerDelegate.
  // Creates a memory dump for the current process and appends it to the trace.
  // |callback| will be invoked asynchronously upon completion on the same
  // thread on which CreateProcessDump() was called.
  void CreateProcessDump(const MemoryDumpRequestArgs& args,
                         const MemoryDumpCallback& callback);

  // Calls InvokeOnMemoryDump() for the next MDP on the task runner specified by
  // the MDP while registration. On failure to do so, skips and continues to
  // next MDP.
  void SetupNextMemoryDump(
      std::unique_ptr<ProcessMemoryDumpAsyncState> pmd_async_state);

  // Invokes OnMemoryDump() of the next MDP and calls SetupNextMemoryDump() at
  // the end to continue the ProcessMemoryDump. Should be called on the MDP task
  // runner.
  void InvokeOnMemoryDump(ProcessMemoryDumpAsyncState* owned_pmd_async_state);

  // Helper for RegierDumpProvider* functions.
  void RegisterDumpProviderInternal(
      MemoryDumpProvider* mdp,
      const char* name,
      scoped_refptr<SequencedTaskRunner> task_runner,
      const MemoryDumpProvider::Options& options);

  // Helper for the public UnregisterDumpProvider* functions.
  void UnregisterDumpProviderInternal(MemoryDumpProvider* mdp,
                                      bool take_mdp_ownership_and_delete_async);

  // An ordererd set of registered MemoryDumpProviderInfo(s), sorted by task
  // runner affinity (MDPs belonging to the same task runners are adjacent).
  MemoryDumpProviderInfo::OrderedSet dump_providers_;

  // Shared among all the PMDs to keep state scoped to the tracing session.
  scoped_refptr<MemoryDumpSessionState> session_state_;

  MemoryDumpManagerDelegate* delegate_;  // Not owned.

  // When true, this instance is in charge of coordinating periodic dumps.
  bool is_coordinator_;

  // Protects from concurrent accesses to the |dump_providers_*| and |delegate_|
  // to guard against disabling logging while dumping on another thread.
  Lock lock_;

  // Optimization to avoid attempting any memory dump (i.e. to not walk an empty
  // dump_providers_enabled_ list) when tracing is not enabled.
  subtle::AtomicWord memory_tracing_enabled_;

  // For time-triggered periodic dumps.
  PeriodicGlobalDumpTimer periodic_dump_timer_;

  // Thread used for MemoryDumpProviders which don't specify a task runner
  // affinity.
  std::unique_ptr<Thread> dump_thread_;

  // The unique id of the child process. This is created only for tracing and is
  // expected to be valid only when tracing is enabled.
  uint64_t tracing_process_id_;

  // When true, calling |RegisterMemoryDumpProvider| is a no-op.
  bool dumper_registrations_ignored_for_testing_;

  // Whether new memory dump providers should be told to enable heap profiling.
  bool heap_profiling_enabled_;

  DISALLOW_COPY_AND_ASSIGN(MemoryDumpManager);
};

// The delegate is supposed to be long lived (read: a Singleton) and thread
// safe (i.e. should expect calls from any thread and handle thread hopping).
class BASE_EXPORT MemoryDumpManagerDelegate {
 public:
  virtual void RequestGlobalMemoryDump(const MemoryDumpRequestArgs& args,
                                       const MemoryDumpCallback& callback) = 0;

  // Returns tracing process id of the current process. This is used by
  // MemoryDumpManager::GetTracingProcessId.
  virtual uint64_t GetTracingProcessId() const = 0;

 protected:
  MemoryDumpManagerDelegate() {}
  virtual ~MemoryDumpManagerDelegate() {}

  void CreateProcessDump(const MemoryDumpRequestArgs& args,
                         const MemoryDumpCallback& callback) {
    MemoryDumpManager::GetInstance()->CreateProcessDump(args, callback);
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryDumpManagerDelegate);
};

}  // namespace trace_event
}  // namespace base

#endif  // BASE_TRACE_EVENT_MEMORY_DUMP_MANAGER_H_
