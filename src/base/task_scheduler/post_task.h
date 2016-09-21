// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TASK_SCHEDULER_POST_TASK_H_
#define BASE_TASK_SCHEDULER_POST_TASK_H_

#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/location.h"
#include "base/memory/ref_counted.h"
#include "base/task_runner.h"
#include "base/task_scheduler/task_traits.h"

namespace base {

// This is the preferred interface to post tasks to the TaskScheduler.
//
// Note: The TaskScheduler is still in an experimental phase in Chrome. Please
// refrain from using this API unless you know what you are doing.
//
// TaskScheduler must have been registered for the current process via
// TaskScheduler::SetInstance() before the functions below are valid.
//
// To post a simple one-off task:
//     PostTask(FROM_HERE, Bind(...));
//
// To post a high priority one-off task to respond to a user interaction:
//     PostTaskWithTraits(
//         FROM_HERE,
//         TaskTraits().WithPriority(TaskPriority::USER_BLOCKING),
//         Bind(...));
//
// To post tasks that must run in sequence:
//     scoped_refptr<TaskRunner> task_runner = CreateTaskRunnerWithTraits(
//         TaskTraits(), ExecutionMode::SEQUENCED);
//     task_runner.PostTask(FROM_HERE, Bind(...));
//     task_runner.PostTask(FROM_HERE, Bind(...));
//
// To post file I/O tasks that must run in sequence and can be skipped on
// shutdown:
//     scoped_refptr<TaskRunner> task_runner =
//         CreateTaskRunnerWithTraits(
//             TaskTraits().WithFileIO().WithShutdownBehavior(
//                 TaskShutdownBehavior::SKIP_ON_SHUTDOWN),
//             ExecutionMode::SEQUENCED);
//     task_runner.PostTask(FROM_HERE, Bind(...));
//     task_runner.PostTask(FROM_HERE, Bind(...));
//
// The default TaskTraits apply to tasks that:
//     (1) don't need to do I/O,
//     (2) don't affect user interaction and/or visible elements, and
//     (3) can either block shutdown or be skipped on shutdown
//         (barring current TaskScheduler default).
// If those loose requirements are sufficient for your task, use
// PostTask[AndReply], otherwise override these with explicit traits via
// PostTaskWithTraits[AndReply].

// Posts |task| to the TaskScheduler. Calling this is equivalent to calling
// PostTaskWithTraits with plain TaskTraits.
BASE_EXPORT void PostTask(const tracked_objects::Location& from_here,
                          const Closure& task);

// Posts |task| to the TaskScheduler and posts |reply| on the caller's execution
// context (i.e. same sequence or thread and same TaskTraits if applicable) when
// |task| completes. Calling this is equivalent to calling
// PostTaskWithTraitsAndReply with plain TaskTraits. Can only be called when
// SequencedTaskRunnerHandle::IsSet().
BASE_EXPORT void PostTaskAndReply(const tracked_objects::Location& from_here,
                                  const Closure& task,
                                  const Closure& reply);

// Posts |task| with specific |traits| to the TaskScheduler.
BASE_EXPORT void PostTaskWithTraits(const tracked_objects::Location& from_here,
                                    TaskTraits traits,
                                    const Closure& task);

// Posts |task| with specific |traits| to the TaskScheduler and posts |reply| on
// the caller's execution context (i.e. same sequence or thread and same
// TaskTraits if applicable) when |task| completes. Can only be called when
// SequencedTaskRunnerHandle::IsSet().
BASE_EXPORT void PostTaskWithTraitsAndReply(
    const tracked_objects::Location& from_here,
    TaskTraits traits,
    const Closure& task,
    const Closure& reply);

// Returns a TaskRunner whose PostTask invocations will result in scheduling
// tasks using |traits| which will be executed according to |execution_mode|.
BASE_EXPORT scoped_refptr<TaskRunner> CreateTaskRunnerWithTraits(
    TaskTraits traits,
    ExecutionMode execution_mode);

}  // namespace base

#endif  // BASE_TASK_SCHEDULER_POST_TASK_H_
