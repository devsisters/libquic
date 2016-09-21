// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/delayed_task_manager.h"

#include <utility>

#include "base/logging.h"
#include "base/task_scheduler/scheduler_worker_pool.h"

namespace base {
namespace internal {

struct DelayedTaskManager::DelayedTask {
  DelayedTask(std::unique_ptr<Task> task,
              scoped_refptr<Sequence> sequence,
              SchedulerWorker* worker,
              SchedulerWorkerPool* worker_pool,
              uint64_t index)
      : task(std::move(task)),
        sequence(std::move(sequence)),
        worker(worker),
        worker_pool(worker_pool),
        index(index) {}

  DelayedTask(DelayedTask&& other) = default;

  ~DelayedTask() = default;

  DelayedTask& operator=(DelayedTask&& other) = default;

  // |task| will be posted to |worker_pool| with |sequence| and |worker|
  // when it becomes ripe for execution.
  std::unique_ptr<Task> task;
  scoped_refptr<Sequence> sequence;
  SchedulerWorker* worker;
  SchedulerWorkerPool* worker_pool;

  // Ensures that tasks that have the same |delayed_run_time| are sorted
  // according to the order in which they were added to the DelayedTaskManager.
  uint64_t index;

 private:
  DISALLOW_COPY_AND_ASSIGN(DelayedTask);
};

DelayedTaskManager::DelayedTaskManager(
    const Closure& on_delayed_run_time_updated)
    : on_delayed_run_time_updated_(on_delayed_run_time_updated) {
  DCHECK(!on_delayed_run_time_updated_.is_null());
}

DelayedTaskManager::~DelayedTaskManager() = default;

void DelayedTaskManager::AddDelayedTask(std::unique_ptr<Task> task,
                                        scoped_refptr<Sequence> sequence,
                                        SchedulerWorker* worker,
                                        SchedulerWorkerPool* worker_pool) {
  DCHECK(task);
  DCHECK(sequence);
  DCHECK(worker_pool);

  const TimeTicks new_task_delayed_run_time = task->delayed_run_time;
  TimeTicks current_delayed_run_time;

  {
    AutoSchedulerLock auto_lock(lock_);

    if (!delayed_tasks_.empty())
      current_delayed_run_time = delayed_tasks_.top().task->delayed_run_time;

    delayed_tasks_.emplace(std::move(task), std::move(sequence), worker,
                           worker_pool, ++delayed_task_index_);
  }

  if (current_delayed_run_time.is_null() ||
      new_task_delayed_run_time < current_delayed_run_time) {
    on_delayed_run_time_updated_.Run();
  }
}

void DelayedTaskManager::PostReadyTasks() {
  const TimeTicks now = Now();

  // Move delayed tasks that are ready for execution into |ready_tasks|. Don't
  // post them right away to avoid imposing an unecessary lock dependency on
  // PostTaskNowHelper.
  std::vector<DelayedTask> ready_tasks;

  {
    AutoSchedulerLock auto_lock(lock_);
    while (!delayed_tasks_.empty() &&
           delayed_tasks_.top().task->delayed_run_time <= now) {
      // The const_cast for std::move is okay since we're immediately popping
      // the task from |delayed_tasks_|. See DelayedTaskComparator::operator()
      // for minor debug-check implications.
      ready_tasks.push_back(
          std::move(const_cast<DelayedTask&>(delayed_tasks_.top())));
      delayed_tasks_.pop();
    }
  }

  // Post delayed tasks that are ready for execution.
  for (auto& delayed_task : ready_tasks) {
    delayed_task.worker_pool->PostTaskWithSequenceNow(
        std::move(delayed_task.task), std::move(delayed_task.sequence),
        delayed_task.worker);
  }
}

TimeTicks DelayedTaskManager::GetDelayedRunTime() const {
  AutoSchedulerLock auto_lock(lock_);

  if (delayed_tasks_.empty())
    return TimeTicks();

  return delayed_tasks_.top().task->delayed_run_time;
}

// In std::priority_queue, the largest element is on top. Therefore, this
// comparator returns true if the delayed run time of |right| is earlier than
// the delayed run time of |left|.
bool DelayedTaskManager::DelayedTaskComparator::operator()(
    const DelayedTask& left,
    const DelayedTask& right) const {
#ifndef NDEBUG
  // Due to STL consistency checks in Windows and const_cast'ing right before
  // popping the DelayedTask, a null task can be passed to this comparator in
  // Debug builds. To satisfy these consistency checks, this comparator
  // considers null tasks to be the larger than anything.
  DCHECK(left.task || right.task);
  if (!left.task)
    return false;
  if (!right.task)
    return true;
#else
  DCHECK(left.task);
  DCHECK(right.task);
#endif  // NDEBUG
  if (left.task->delayed_run_time > right.task->delayed_run_time)
    return true;
  if (left.task->delayed_run_time < right.task->delayed_run_time)
    return false;
  return left.index > right.index;
}

TimeTicks DelayedTaskManager::Now() const {
  return TimeTicks::Now();
}

}  // namespace internal
}  // namespace base
