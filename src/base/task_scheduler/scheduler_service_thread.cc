// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_service_thread.h"

#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/scheduler_worker.h"
#include "base/task_scheduler/sequence.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"

namespace base {
namespace internal {
namespace {

class ServiceThreadDelegate : public SchedulerWorker::Delegate {
 public:
  ServiceThreadDelegate(DelayedTaskManager* delayed_task_manager)
      : delayed_task_manager_(delayed_task_manager) {}

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker,
                   const TimeDelta& detach_duration) override {
    DCHECK(detach_duration.is_max());
  }

  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override {
    delayed_task_manager_->PostReadyTasks();
    return nullptr;
  }

  void DidRunTask(const Task* task, const TimeDelta& task_latency) override {
    NOTREACHED()
        << "GetWork() never returns a sequence so no task should ever run.";
  }

  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override {
    NOTREACHED() <<
        "GetWork() never returns a sequence so there's nothing to reenqueue.";
  }

  TimeDelta GetSleepTimeout() override {
    const TimeTicks next_time = delayed_task_manager_->GetDelayedRunTime();
    if (next_time.is_null())
      return TimeDelta::Max();

    // For delayed tasks with delays that are really close to each other, it is
    // possible for the current time to advance beyond the required
    // GetDelayedWaitTime. Return a minimum of TimeDelta() in the event that
    // happens.
    TimeDelta sleep_time = next_time - delayed_task_manager_->Now();
    const TimeDelta zero_delta;
    return sleep_time < zero_delta ? zero_delta : sleep_time;
  }

  bool CanDetach(SchedulerWorker* worker) override {
    return false;
  }

 private:
  DelayedTaskManager* const delayed_task_manager_;

  DISALLOW_COPY_AND_ASSIGN(ServiceThreadDelegate);
};

}  // namespace

SchedulerServiceThread::~SchedulerServiceThread() = default;

// static
std::unique_ptr<SchedulerServiceThread> SchedulerServiceThread::Create(
    TaskTracker* task_tracker, DelayedTaskManager* delayed_task_manager) {
  std::unique_ptr<SchedulerWorker> worker = SchedulerWorker::Create(
      ThreadPriority::NORMAL,
      MakeUnique<ServiceThreadDelegate>(delayed_task_manager), task_tracker,
      SchedulerWorker::InitialState::ALIVE);
  if (!worker)
    return nullptr;

  return WrapUnique(new SchedulerServiceThread(std::move(worker)));
}

void SchedulerServiceThread::WakeUp() {
  worker_->WakeUp();
}

void SchedulerServiceThread::JoinForTesting() {
  worker_->JoinForTesting();
}

SchedulerServiceThread::SchedulerServiceThread(
    std::unique_ptr<SchedulerWorker> worker) : worker_(std::move(worker)) {}

}  // namespace internal
}  // namespace base
