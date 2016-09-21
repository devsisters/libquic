// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker.h"

#include <stddef.h>

#include <utility>

#include "base/logging.h"
#include "base/task_scheduler/task_tracker.h"
#include "build/build_config.h"

#if defined(OS_MACOSX)
#include "base/mac/scoped_nsautorelease_pool.h"
#endif

namespace base {
namespace internal {

class SchedulerWorker::Thread : public PlatformThread::Delegate {
 public:
  ~Thread() override = default;

  static std::unique_ptr<Thread> Create(SchedulerWorker* outer) {
    std::unique_ptr<Thread> thread(new Thread(outer));
    thread->Initialize();
    if (thread->thread_handle_.is_null())
      return nullptr;
    return thread;
  }

  // PlatformThread::Delegate.
  void ThreadMain() override {
    // Set if this thread was detached.
    std::unique_ptr<Thread> detached_thread;

    outer_->delegate_->OnMainEntry(
        outer_, outer_->last_detach_time_.is_null()
                    ? TimeDelta::Max()
                    : TimeTicks::Now() - outer_->last_detach_time_);

    // A SchedulerWorker starts out waiting for work.
    WaitForWork();

    while (!outer_->task_tracker_->IsShutdownComplete() &&
           !outer_->ShouldExitForTesting()) {
      DCHECK(outer_);

#if defined(OS_MACOSX)
      mac::ScopedNSAutoreleasePool autorelease_pool;
#endif

      UpdateThreadPriority(GetDesiredThreadPriority());

      // Get the sequence containing the next task to execute.
      scoped_refptr<Sequence> sequence = outer_->delegate_->GetWork(outer_);
      if (!sequence) {
        if (outer_->delegate_->CanDetach(outer_)) {
          detached_thread = outer_->Detach();
          if (detached_thread) {
            DCHECK_EQ(detached_thread.get(), this);
            PlatformThread::Detach(thread_handle_);
            outer_ = nullptr;
            break;
          }
        }
        WaitForWork();
        continue;
      }

      const Task* task = sequence->PeekTask();
      const TimeTicks start_time = TimeTicks::Now();
      if (outer_->task_tracker_->RunTask(task, sequence->token()))
        outer_->delegate_->DidRunTask(task, start_time - task->sequenced_time);

      const bool sequence_became_empty = sequence->PopTask();

      // If |sequence| isn't empty immediately after the pop, re-enqueue it to
      // maintain the invariant that a non-empty Sequence is always referenced
      // by either a PriorityQueue or a SchedulerWorker. If it is empty
      // and there are live references to it, it will be enqueued when a Task is
      // added to it. Otherwise, it will be destroyed at the end of this scope.
      if (!sequence_became_empty)
        outer_->delegate_->ReEnqueueSequence(std::move(sequence));

      // Calling WakeUp() guarantees that this SchedulerWorker will run
      // Tasks from Sequences returned by the GetWork() method of |delegate_|
      // until it returns nullptr. Resetting |wake_up_event_| here doesn't break
      // this invariant and avoids a useless loop iteration before going to
      // sleep if WakeUp() is called while this SchedulerWorker is awake.
      wake_up_event_.Reset();
    }

    // If a wake up is pending and we successfully detached, somehow |outer_|
    // was able to signal us which means it probably thinks we're still alive.
    // This is bad as it will cause the WakeUp to no-op and |outer_| will be
    // stuck forever.
    DCHECK(!detached_thread || !IsWakeUpPending()) <<
        "This thread was detached and woken up at the same time.";
  }

  void Join() { PlatformThread::Join(thread_handle_); }

  void WakeUp() { wake_up_event_.Signal(); }

  bool IsWakeUpPending() { return wake_up_event_.IsSignaled(); }

 private:
  Thread(SchedulerWorker* outer)
      : outer_(outer),
        wake_up_event_(WaitableEvent::ResetPolicy::MANUAL,
                       WaitableEvent::InitialState::NOT_SIGNALED),
        current_thread_priority_(GetDesiredThreadPriority()) {
    DCHECK(outer_);
  }

  void Initialize() {
    constexpr size_t kDefaultStackSize = 0;
    PlatformThread::CreateWithPriority(kDefaultStackSize, this, &thread_handle_,
                                       current_thread_priority_);
  }

  void WaitForWork() {
    DCHECK(outer_);
    const TimeDelta sleep_time = outer_->delegate_->GetSleepTimeout();
    if (sleep_time.is_max()) {
      // Calling TimedWait with TimeDelta::Max is not recommended per
      // http://crbug.com/465948.
      wake_up_event_.Wait();
    } else {
      wake_up_event_.TimedWait(sleep_time);
    }
    wake_up_event_.Reset();
  }

  // Returns the priority for which the thread should be set based on the
  // priority hint, current shutdown state, and platform capabilities.
  ThreadPriority GetDesiredThreadPriority() {
    DCHECK(outer_);

    // All threads have a NORMAL priority when Lock doesn't handle multiple
    // thread priorities.
    if (!Lock::HandlesMultipleThreadPriorities())
      return ThreadPriority::NORMAL;

    // To avoid shutdown hangs, disallow a priority below NORMAL during
    // shutdown. If thread priority cannot be increased, never allow a priority
    // below NORMAL.
    if (static_cast<int>(outer_->priority_hint_) <
            static_cast<int>(ThreadPriority::NORMAL) &&
        (outer_->task_tracker_->HasShutdownStarted() ||
         !PlatformThread::CanIncreaseCurrentThreadPriority())) {
      return ThreadPriority::NORMAL;
    }

    return outer_->priority_hint_;
  }

  void UpdateThreadPriority(ThreadPriority desired_thread_priority) {
    if (desired_thread_priority == current_thread_priority_)
      return;

    PlatformThread::SetCurrentThreadPriority(desired_thread_priority);
    current_thread_priority_ = desired_thread_priority;
  }

  PlatformThreadHandle thread_handle_;

  SchedulerWorker* outer_;

  // Event signaled to wake up this thread.
  WaitableEvent wake_up_event_;

  // Current priority of this thread. May be different from
  // |outer_->priority_hint_|.
  ThreadPriority current_thread_priority_;

  DISALLOW_COPY_AND_ASSIGN(Thread);
};

std::unique_ptr<SchedulerWorker> SchedulerWorker::Create(
    ThreadPriority priority_hint,
    std::unique_ptr<Delegate> delegate,
    TaskTracker* task_tracker,
    InitialState initial_state) {
  std::unique_ptr<SchedulerWorker> worker(
      new SchedulerWorker(priority_hint, std::move(delegate), task_tracker));
  // Creation happens before any other thread can reference this one, so no
  // synchronization is necessary.
  if (initial_state == SchedulerWorker::InitialState::ALIVE) {
    worker->CreateThread();
    if (!worker->thread_) {
      return nullptr;
    }
  }

  return worker;
}

SchedulerWorker::~SchedulerWorker() {
  // It is unexpected for |thread_| to be alive and for SchedulerWorker to
  // destroy since SchedulerWorker owns the delegate needed by |thread_|.
  // For testing, this generally means JoinForTesting was not called.
  DCHECK(!thread_);
}

void SchedulerWorker::WakeUp() {
  AutoSchedulerLock auto_lock(thread_lock_);
  if (!thread_)
    CreateThreadAssertSynchronized();

  if (thread_)
    thread_->WakeUp();
}

void SchedulerWorker::JoinForTesting() {
  {
    AutoSchedulerLock auto_lock(should_exit_for_testing_lock_);
    should_exit_for_testing_ = true;
  }
  WakeUp();

  // Normally holding a lock and joining is dangerous. However, since this is
  // only for testing, we're okay since the only scenario that could impact this
  // is a call to Detach, which is disallowed by having the delegate always
  // return false for the CanDetach call.
  AutoSchedulerLock auto_lock(thread_lock_);
  if (thread_)
    thread_->Join();

  thread_.reset();
}

bool SchedulerWorker::ThreadAliveForTesting() const {
  AutoSchedulerLock auto_lock(thread_lock_);
  return !!thread_;
}

SchedulerWorker::SchedulerWorker(ThreadPriority priority_hint,
                                 std::unique_ptr<Delegate> delegate,
                                 TaskTracker* task_tracker)
    : priority_hint_(priority_hint),
      delegate_(std::move(delegate)),
      task_tracker_(task_tracker) {
  DCHECK(delegate_);
  DCHECK(task_tracker_);
}

std::unique_ptr<SchedulerWorker::Thread> SchedulerWorker::Detach() {
  DCHECK(!ShouldExitForTesting()) << "Worker was already joined";
  AutoSchedulerLock auto_lock(thread_lock_);
  // If a wakeup is pending, then a WakeUp() came in while we were deciding to
  // detach. This means we can't go away anymore since we would break the
  // guarantee that we call GetWork() after a successful wakeup.
  if (thread_->IsWakeUpPending())
    return nullptr;
  last_detach_time_ = TimeTicks::Now();
  return std::move(thread_);
}

void SchedulerWorker::CreateThread() {
  thread_ = Thread::Create(this);
}

void SchedulerWorker::CreateThreadAssertSynchronized() {
  thread_lock_.AssertAcquired();
  CreateThread();
}

bool SchedulerWorker::ShouldExitForTesting() const {
  AutoSchedulerLock auto_lock(should_exit_for_testing_lock_);
  return should_exit_for_testing_;
}

}  // namespace internal
}  // namespace base
