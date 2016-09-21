// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_SERVICE_THREAD_H_
#define BASE_TASK_SCHEDULER_SERVICE_THREAD_H_

#include <memory>

#include "base/base_export.h"
#include "base/macros.h"

namespace base {
namespace internal {

class DelayedTaskManager;
class SchedulerWorker;
class TaskTracker;

// A thread dedicated to performing Task Scheduler related work.
class BASE_EXPORT SchedulerServiceThread {
 public:
  ~SchedulerServiceThread();

  // Creates a SchedulerServiceThread. |task_tracker| and |delayed_task_manager|
  // are passed through to the underlying SchedulerWorker. Returns a nullptr on
  // failure.
  static std::unique_ptr<SchedulerServiceThread> Create(
      TaskTracker* task_tracker, DelayedTaskManager* delayed_task_manager);

  // Wakes the SchedulerServiceThread if it wasn't already awake. This also has
  // the impact of updating the amount of time the thread sleeps for delayed
  // tasks.
  void WakeUp();

  // Joins this SchedulerServiceThread. This can only be called once.
  void JoinForTesting();

 private:
  SchedulerServiceThread(std::unique_ptr<SchedulerWorker> worker);

  const std::unique_ptr<SchedulerWorker> worker_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerServiceThread);
};

}  // namespace internal
}  // namespace base

#endif  // BASE_TASK_SCHEDULER_SERVICE_THREAD_H_
