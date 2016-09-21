// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/post_task.h"

#include "base/task_scheduler/task_scheduler.h"
#include "base/threading/post_task_and_reply_impl.h"

namespace base {

namespace {

class PostTaskAndReplyTaskRunner : public internal::PostTaskAndReplyImpl {
 public:
  explicit PostTaskAndReplyTaskRunner(TaskTraits traits)
      : traits_(traits) {}

 private:
  bool PostTask(const tracked_objects::Location& from_here,
                const Closure& task) override {
    PostTaskWithTraits(from_here, traits_, task);
    return true;
  }

  const TaskTraits traits_;
};


}  // namespace

void PostTask(const tracked_objects::Location& from_here, const Closure& task) {
  PostTaskWithTraits(from_here, TaskTraits(), task);
}

void PostTaskAndReply(const tracked_objects::Location& from_here,
                      const Closure& task,
                      const Closure& reply) {
  PostTaskWithTraitsAndReply(from_here, TaskTraits(), task, reply);
}

void PostTaskWithTraits(const tracked_objects::Location& from_here,
                        TaskTraits traits,
                        const Closure& task) {
  TaskScheduler::GetInstance()->PostTaskWithTraits(from_here, traits, task);
}

void PostTaskWithTraitsAndReply(const tracked_objects::Location& from_here,
                                TaskTraits traits,
                                const Closure& task,
                                const Closure& reply) {
  PostTaskAndReplyTaskRunner(traits).PostTaskAndReply(from_here, task, reply);
}

scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
    TaskTraits traits,
    ExecutionMode execution_mode) {
  return TaskScheduler::GetInstance()->CreateTaskRunnerWithTraits(
      traits, execution_mode);
}

}  // namespace base
