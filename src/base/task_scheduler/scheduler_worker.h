// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_
#define BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/sequence.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"

namespace base {
namespace internal {

class TaskTracker;

// A worker that manages a single thread to run Tasks from Sequences returned
// by a delegate.
//
// A SchedulerWorker starts out sleeping. It is woken up by a call to WakeUp().
// After a wake-up, a SchedulerWorker runs Tasks from Sequences returned by the
// GetWork() method of its delegate as long as it doesn't return nullptr. It
// also periodically checks with its TaskTracker whether shutdown has completed
// and exits when it has.
//
// The worker is free to release and reallocate the platform thread with
// guidance from the delegate.
//
// This class is thread-safe.
class BASE_EXPORT SchedulerWorker {
 public:
  // Delegate interface for SchedulerWorker. The methods are always called from
  // a thread managed by the SchedulerWorker instance.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Called by a thread managed by |worker| when it enters its main function.
    // If a thread is recreated after detachment, |detach_duration| is the time
    // elapsed since detachment. Otherwise, if this is the first thread created
    // for |worker|, |detach_duration| is TimeDelta::Max().
    virtual void OnMainEntry(SchedulerWorker* worker,
                             const TimeDelta& detach_duration) = 0;

    // Called by a thread managed by |worker| to get a Sequence from which to
    // run a Task.
    virtual scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) = 0;

    // Called by the SchedulerWorker after it ran |task|. |task_latency| is the
    // time elapsed between when the task was posted and when it started to run.
    virtual void DidRunTask(const Task* task,
                            const TimeDelta& task_latency) = 0;

    // Called when |sequence| isn't empty after the SchedulerWorker pops a Task
    // from it. |sequence| is the last Sequence returned by GetWork().
    virtual void ReEnqueueSequence(scoped_refptr<Sequence> sequence) = 0;

    // Called by a thread to determine how long to sleep before the next call to
    // GetWork(). GetWork() may be called before this timeout expires if the
    // worker's WakeUp() method is called.
    virtual TimeDelta GetSleepTimeout() = 0;

    // Called by a thread if it is allowed to detach if the last call to
    // GetWork() returned nullptr.
    //
    // It is the responsibility of the delegate to determine if detachment is
    // safe. If the delegate is responsible for thread-affine work, detachment
    // is generally not safe.
    //
    // When true is returned:
    // - The next WakeUp() could be more costly due to new thread creation.
    // - The worker will take this as a signal that it can detach, but it is not
    //   obligated to do so.
    // This MUST return false if SchedulerWorker::JoinForTesting() is in
    // progress.
    virtual bool CanDetach(SchedulerWorker* worker) = 0;
  };

  enum class InitialState { ALIVE, DETACHED };

  // Creates a SchedulerWorker that runs Tasks from Sequences returned by
  // |delegate|. |priority_hint| is the preferred thread priority; the actual
  // thread priority depends on shutdown state and platform capabilities.
  // |task_tracker| is used to handle shutdown behavior of Tasks. If
  // |worker_state| is DETACHED, the thread will be created upon a WakeUp().
  // Returns nullptr if creating the underlying platform thread fails during
  // Create().
  static std::unique_ptr<SchedulerWorker> Create(
      ThreadPriority priority_hint,
      std::unique_ptr<Delegate> delegate,
      TaskTracker* task_tracker,
      InitialState initial_state);

  // Destroying a SchedulerWorker in production is not allowed; it is always
  // leaked. In tests, it can only be destroyed after JoinForTesting() has
  // returned.
  ~SchedulerWorker();

  // Wakes up this SchedulerWorker if it wasn't already awake. After this
  // is called, this SchedulerWorker will run Tasks from Sequences
  // returned by the GetWork() method of its delegate until it returns nullptr.
  // WakeUp() may fail if the worker is detached and it fails to allocate a new
  // worker. If this happens, there will be no call to GetWork().
  void WakeUp();

  SchedulerWorker::Delegate* delegate() { return delegate_.get(); }

  // Joins this SchedulerWorker. If a Task is already running, it will be
  // allowed to complete its execution. This can only be called once.
  void JoinForTesting();

  // Returns true if the worker is alive.
  bool ThreadAliveForTesting() const;

 private:
  class Thread;

  SchedulerWorker(ThreadPriority thread_priority,
                  std::unique_ptr<Delegate> delegate,
                  TaskTracker* task_tracker);

  // Returns the thread instance if the detach was successful so that it can be
  // freed upon termination of the thread.
  // If the detach is not possible, returns nullptr.
  std::unique_ptr<SchedulerWorker::Thread> Detach();

  void CreateThread();

  void CreateThreadAssertSynchronized();

  bool ShouldExitForTesting() const;

  // Synchronizes access to |thread_|.
  mutable SchedulerLock thread_lock_;

  // The underlying thread for this SchedulerWorker.
  std::unique_ptr<Thread> thread_;

  // Time of the last successful Detach(). Is only accessed from the thread
  // managed by this SchedulerWorker.
  TimeTicks last_detach_time_;

  const ThreadPriority priority_hint_;
  const std::unique_ptr<Delegate> delegate_;
  TaskTracker* const task_tracker_;

  // Synchronizes access to |should_exit_for_testing_|.
  mutable SchedulerLock should_exit_for_testing_lock_;

  // True once JoinForTesting() has been called.
  bool should_exit_for_testing_ = false;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorker);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SCHEDULER_WORKER_H_
