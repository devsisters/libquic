// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/sequence.h"

#include <utility>

#include "base/logging.h"
#include "base/time/time.h"

namespace base {
namespace internal {

Sequence::Sequence() = default;

bool Sequence::PushTask(std::unique_ptr<Task> task) {
  DCHECK(task->sequenced_time.is_null());
  task->sequenced_time = base::TimeTicks::Now();

  AutoSchedulerLock auto_lock(lock_);
  ++num_tasks_per_priority_[static_cast<int>(task->traits.priority())];
  queue_.push(std::move(task));

  // Return true if the sequence was empty before the push.
  return queue_.size() == 1;
}

const Task* Sequence::PeekTask() const {
  AutoSchedulerLock auto_lock(lock_);

  if (queue_.empty())
    return nullptr;

  return queue_.front().get();
}

bool Sequence::PopTask() {
  // Delete the popped task outside the scope of |lock_|. This prevents a double
  // acquisition of |lock_| if the task's destructor tries to post a task to
  // this Sequence and reduces contention.
  std::unique_ptr<Task> delete_outside_lock_scope;
  bool sequence_empty_after_pop = false;

  {
    AutoSchedulerLock auto_lock(lock_);
    DCHECK(!queue_.empty());

    const int priority_index =
        static_cast<int>(queue_.front()->traits.priority());
    DCHECK_GT(num_tasks_per_priority_[priority_index], 0U);
    --num_tasks_per_priority_[priority_index];

    delete_outside_lock_scope = std::move(queue_.front());
    queue_.pop();
    sequence_empty_after_pop = queue_.empty();
  }

  return sequence_empty_after_pop;
}

SequenceSortKey Sequence::GetSortKey() const {
  TaskPriority priority = TaskPriority::LOWEST;
  base::TimeTicks next_task_sequenced_time;

  {
    AutoSchedulerLock auto_lock(lock_);
    DCHECK(!queue_.empty());

    // Find the highest task priority in the sequence.
    const int highest_priority_index = static_cast<int>(TaskPriority::HIGHEST);
    const int lowest_priority_index = static_cast<int>(TaskPriority::LOWEST);
    for (int i = highest_priority_index; i > lowest_priority_index; --i) {
      if (num_tasks_per_priority_[i] > 0) {
        priority = static_cast<TaskPriority>(i);
        break;
      }
    }

    // Save the sequenced time of the next task in the sequence.
    next_task_sequenced_time = queue_.front()->sequenced_time;
  }

  return SequenceSortKey(priority, next_task_sequenced_time);
}

Sequence::~Sequence() = default;

}  // namespace internal
}  // namespace base
