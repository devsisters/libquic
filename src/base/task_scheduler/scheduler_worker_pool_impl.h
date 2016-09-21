// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_

#include <stddef.h>

#include <memory>
#include <string>
#include <vector>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/atomic_flag.h"
#include "base/synchronization/condition_variable.h"
#include "base/task_runner.h"
#include "base/task_scheduler/priority_queue.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/scheduler_worker.h"
#include "base/task_scheduler/scheduler_worker_pool.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/scheduler_worker_stack.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_traits.h"
#include "base/threading/platform_thread.h"

namespace base {

class HistogramBase;
class TimeDelta;

namespace internal {

class DelayedTaskManager;
class TaskTracker;

// A pool of workers that run Tasks. This class is thread-safe.
class BASE_EXPORT SchedulerWorkerPoolImpl : public SchedulerWorkerPool {
 public:
  // Callback invoked when a Sequence isn't empty after a worker pops a Task
  // from it.
  using ReEnqueueSequenceCallback = Callback<void(scoped_refptr<Sequence>)>;

  // Destroying a SchedulerWorkerPoolImpl returned by Create() is not allowed in
  // production; it is always leaked. In tests, it can only be destroyed after
  // JoinForTesting() has returned.
  ~SchedulerWorkerPoolImpl() override;

  // Creates a SchedulerWorkerPoolImpl following the |worker_pool_params|
  // specification. |re_enqueue_sequence_callback| will be invoked after a
  // worker of this worker pool tries to run a Task. |task_tracker| is used to
  // handle shutdown behavior of Tasks. |delayed_task_manager| handles Tasks
  // posted with a delay. Returns nullptr on failure to create a worker pool
  // with at least one thread.
  static std::unique_ptr<SchedulerWorkerPoolImpl> Create(
      const SchedulerWorkerPoolParams& params,
      const ReEnqueueSequenceCallback& re_enqueue_sequence_callback,
      TaskTracker* task_tracker,
      DelayedTaskManager* delayed_task_manager);

  // Waits until all workers are idle.
  void WaitForAllWorkersIdleForTesting();

  // Joins all workers of this worker pool. Tasks that are already running are
  // allowed to complete their execution. This can only be called once.
  void JoinForTesting();

  // Disallows worker thread detachment. If the suggested reclaim time is not
  // TimeDelta::Max(), then the test should call this before the detach code can
  // run. The safest place to do this is before the a set of work is dispatched
  // (the worker pool is idle and steady state) or before the last
  // synchronization point for all workers (all threads are busy and can't be
  // reclaimed).
  void DisallowWorkerDetachmentForTesting();

  // SchedulerWorkerPool:
  scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
      const TaskTraits& traits,
      ExecutionMode execution_mode) override;
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence,
                         const SequenceSortKey& sequence_sort_key) override;
  bool PostTaskWithSequence(std::unique_ptr<Task> task,
                            scoped_refptr<Sequence> sequence,
                            SchedulerWorker* worker) override;
  void PostTaskWithSequenceNow(std::unique_ptr<Task> task,
                               scoped_refptr<Sequence> sequence,
                               SchedulerWorker* worker) override;

 private:
  class SchedulerSingleThreadTaskRunner;
  class SchedulerWorkerDelegateImpl;

  SchedulerWorkerPoolImpl(StringPiece name,
                          SchedulerWorkerPoolParams::IORestriction
                              io_restriction,
                          const TimeDelta& suggested_reclaim_time,
                          TaskTracker* task_tracker,
                          DelayedTaskManager* delayed_task_manager);

  bool Initialize(
      ThreadPriority priority_hint,
      size_t max_threads,
      const ReEnqueueSequenceCallback& re_enqueue_sequence_callback);

  // Wakes up the last worker from this worker pool to go idle, if any.
  void WakeUpOneWorker();

  // Adds |worker| to |idle_workers_stack_|.
  void AddToIdleWorkersStack(SchedulerWorker* worker);

  // Peeks from |idle_workers_stack_|.
  const SchedulerWorker* PeekAtIdleWorkersStack() const;

  // Removes |worker| from |idle_workers_stack_|.
  void RemoveFromIdleWorkersStack(SchedulerWorker* worker);

  // Returns true if worker thread detachment is permitted.
  bool CanWorkerDetachForTesting();

  // The name of this worker pool, used to label its worker threads.
  const std::string name_;

  // All worker owned by this worker pool. Only modified during initialization
  // of the worker pool.
  std::vector<std::unique_ptr<SchedulerWorker>> workers_;

  // Synchronizes access to |next_worker_index_|.
  SchedulerLock next_worker_index_lock_;

  // Index of the worker that will be assigned to the next single-threaded
  // TaskRunner returned by this pool.
  size_t next_worker_index_ = 0;

  // PriorityQueue from which all threads of this worker pool get work.
  PriorityQueue shared_priority_queue_;

  // Indicates whether Tasks on this worker pool are allowed to make I/O calls.
  const SchedulerWorkerPoolParams::IORestriction io_restriction_;

  // Suggested reclaim time for workers.
  const TimeDelta suggested_reclaim_time_;

  // Synchronizes access to |idle_workers_stack_| and
  // |idle_workers_stack_cv_for_testing_|. Has |shared_priority_queue_|'s
  // lock as its predecessor so that a worker can be pushed to
  // |idle_workers_stack_| within the scope of a Transaction (more
  // details in GetWork()).
  mutable SchedulerLock idle_workers_stack_lock_;

  // Stack of idle workers.
  SchedulerWorkerStack idle_workers_stack_;

  // Signaled when all workers become idle.
  std::unique_ptr<ConditionVariable> idle_workers_stack_cv_for_testing_;

  // Signaled once JoinForTesting() has returned.
  WaitableEvent join_for_testing_returned_;

  // Indicates to the delegates that workers are not permitted to detach their
  // threads.
  AtomicFlag worker_detachment_disallowed_;

#if DCHECK_IS_ON()
  // Signaled when all workers have been created.
  WaitableEvent workers_created_;
#endif

  // TaskScheduler.DetachDuration.[worker pool name] histogram. Intentionally
  // leaked.
  HistogramBase* const detach_duration_histogram_;

  // TaskScheduler.TaskLatency.[worker pool name].[task priority] histograms.
  // Indexed by task priority. Histograms are allocated on demand to reduce
  // memory usage (some task priorities might never run in this
  // SchedulerThreadPoolImpl). Intentionally leaked.
  subtle::AtomicWord
      task_latency_histograms_[static_cast<int>(TaskPriority::HIGHEST) + 1] =
          {};

  TaskTracker* const task_tracker_;
  DelayedTaskManager* const delayed_task_manager_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerPoolImpl);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_WORKER_POOL_IMPL_H_
