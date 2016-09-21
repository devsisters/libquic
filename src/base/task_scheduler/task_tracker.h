// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_TASK_TRACKER_H_
#define BASE_TASK_SCHEDULER_TASK_TRACKER_H_

#include <memory>

#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/scheduler_lock.h"
#include "base/task_scheduler/sequence.h"
#include "base/task_scheduler/task.h"
#include "base/task_scheduler/task_traits.h"

namespace base {

class SequenceToken;

namespace internal {

// All tasks go through the scheduler's TaskTracker when they are posted and
// when they are executed. The TaskTracker enforces shutdown semantics and takes
// care of tracing and profiling. This class is thread-safe.
class BASE_EXPORT TaskTracker {
 public:
  TaskTracker();
  ~TaskTracker();

  // Synchronously shuts down the scheduler. Once this is called, only tasks
  // posted with the BLOCK_SHUTDOWN behavior will be run. Returns when:
  // - All SKIP_ON_SHUTDOWN tasks that were already running have completed their
  //   execution.
  // - All posted BLOCK_SHUTDOWN tasks have completed their execution.
  // CONTINUE_ON_SHUTDOWN tasks still may be running after Shutdown returns.
  // This can only be called once.
  void Shutdown();

  // Informs this TaskTracker that |task| is about to be posted. Returns true if
  // this operation is allowed (|task| should be posted if-and-only-if it is).
  bool WillPostTask(const Task* task);

  // Runs |task| unless the current shutdown state prevents that.
  // |sequence_token| is the token identifying the sequence from which |task|
  // was extracted. Returns true if |task| ran. WillPostTask() must have allowed
  // |task| to be posted before this is called.
  bool RunTask(const Task* task, const SequenceToken& sequence_token);

  // Returns true once shutdown has started (Shutdown() has been called but
  // might not have returned). Note: sequential consistency with the thread
  // calling Shutdown() (or SetHasShutdownStartedForTesting()) isn't guaranteed
  // by this call.
  bool HasShutdownStarted() const;

  // Returns true if shutdown has completed (Shutdown() has returned).
  bool IsShutdownComplete() const;

  // Causes HasShutdownStarted() to return true. Unlike when Shutdown() returns,
  // IsShutdownComplete() won't return true after this returns. Shutdown()
  // cannot be called after this.
  void SetHasShutdownStartedForTesting();

 private:
  class State;

  // Called before WillPostTask() informs the tracing system that a task has
  // been posted. Updates |num_tasks_blocking_shutdown_| if necessary and
  // returns true if the current shutdown state allows the task to be posted.
  bool BeforePostTask(TaskShutdownBehavior shutdown_behavior);

  // Called before a task with |shutdown_behavior| is run by RunTask(). Updates
  // |num_tasks_blocking_shutdown_| if necessary and returns true if the current
  // shutdown state allows the task to be run.
  bool BeforeRunTask(TaskShutdownBehavior shutdown_behavior);

  // Called after a task with |shutdown_behavior| has been run by RunTask().
  // Updates |num_tasks_blocking_shutdown_| and signals |shutdown_cv_| if
  // necessary.
  void AfterRunTask(TaskShutdownBehavior shutdown_behavior);

  // Called when the number of tasks blocking shutdown becomes zero after
  // shutdown has started.
  void OnBlockingShutdownTasksComplete();

  // Number of tasks blocking shutdown and boolean indicating whether shutdown
  // has started.
  const std::unique_ptr<State> state_;

  // Synchronizes access to shutdown related members below.
  mutable SchedulerLock shutdown_lock_;

  // Event instantiated when shutdown starts and signaled when shutdown
  // completes.
  std::unique_ptr<WaitableEvent> shutdown_event_;

  // Number of BLOCK_SHUTDOWN tasks posted during shutdown.
  HistogramBase::Sample num_block_shutdown_tasks_posted_during_shutdown_ = 0;

  DISALLOW_COPY_AND_ASSIGN(TaskTracker);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_TASK_TRACKER_H_
