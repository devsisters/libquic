// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/task_scheduler_impl.h"

#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/task_scheduler/scheduler_service_thread.h"
#include "base/task_scheduler/scheduler_worker_pool_params.h"
#include "base/task_scheduler/sequence_sort_key.h"
#include "base/task_scheduler/task.h"
#include "base/time/time.h"

namespace base {
namespace internal {

// static
std::unique_ptr<TaskSchedulerImpl> TaskSchedulerImpl::Create(
    const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector,
    const WorkerPoolIndexForTraitsCallback&
        worker_pool_index_for_traits_callback) {
  std::unique_ptr<TaskSchedulerImpl> scheduler(
      new TaskSchedulerImpl(worker_pool_index_for_traits_callback));
  scheduler->Initialize(worker_pool_params_vector);
  return scheduler;
}

TaskSchedulerImpl::~TaskSchedulerImpl() {
#if DCHECK_IS_ON()
  DCHECK(join_for_testing_returned_.IsSet());
#endif
}

void TaskSchedulerImpl::PostTaskWithTraits(
    const tracked_objects::Location& from_here,
    const TaskTraits& traits,
    const Closure& task) {
  // Post |task| as part of a one-off single-task Sequence.
  GetWorkerPoolForTraits(traits)->PostTaskWithSequence(
      MakeUnique<Task>(from_here, task, traits, TimeDelta()),
      make_scoped_refptr(new Sequence), nullptr);
}

scoped_refptr<TaskRunner> TaskSchedulerImpl::CreateTaskRunnerWithTraits(
    const TaskTraits& traits,
    ExecutionMode execution_mode) {
  return GetWorkerPoolForTraits(traits)->CreateTaskRunnerWithTraits(
      traits, execution_mode);
}

void TaskSchedulerImpl::Shutdown() {
  // TODO(fdoray): Increase the priority of BACKGROUND tasks blocking shutdown.
  task_tracker_.Shutdown();
}

void TaskSchedulerImpl::JoinForTesting() {
#if DCHECK_IS_ON()
  DCHECK(!join_for_testing_returned_.IsSet());
#endif
  for (const auto& worker_pool : worker_pools_)
    worker_pool->JoinForTesting();
  service_thread_->JoinForTesting();
#if DCHECK_IS_ON()
  join_for_testing_returned_.Set();
#endif
}

TaskSchedulerImpl::TaskSchedulerImpl(const WorkerPoolIndexForTraitsCallback&
                                         worker_pool_index_for_traits_callback)
    : delayed_task_manager_(
          Bind(&TaskSchedulerImpl::OnDelayedRunTimeUpdated, Unretained(this))),
      worker_pool_index_for_traits_callback_(
          worker_pool_index_for_traits_callback)
{
  DCHECK(!worker_pool_index_for_traits_callback_.is_null());
}

void TaskSchedulerImpl::Initialize(
    const std::vector<SchedulerWorkerPoolParams>& worker_pool_params_vector) {
  DCHECK(!worker_pool_params_vector.empty());

  const SchedulerWorkerPoolImpl::ReEnqueueSequenceCallback
      re_enqueue_sequence_callback =
          Bind(&TaskSchedulerImpl::ReEnqueueSequenceCallback, Unretained(this));

  for (const auto& worker_pool_params : worker_pool_params_vector) {
    // Passing pointers to objects owned by |this| to
    // SchedulerWorkerPoolImpl::Create() is safe because a TaskSchedulerImpl
    // can't be deleted before all its worker pools have been joined.
    worker_pools_.push_back(SchedulerWorkerPoolImpl::Create(
        worker_pool_params, re_enqueue_sequence_callback, &task_tracker_,
        &delayed_task_manager_));
    CHECK(worker_pools_.back());
  }

  service_thread_ = SchedulerServiceThread::Create(&task_tracker_,
                                                   &delayed_task_manager_);
  CHECK(service_thread_);
}

SchedulerWorkerPool* TaskSchedulerImpl::GetWorkerPoolForTraits(
    const TaskTraits& traits) {
  const size_t index = worker_pool_index_for_traits_callback_.Run(traits);
  DCHECK_LT(index, worker_pools_.size());
  return worker_pools_[index].get();
}

void TaskSchedulerImpl::ReEnqueueSequenceCallback(
    scoped_refptr<Sequence> sequence) {
  DCHECK(sequence);

  const SequenceSortKey sort_key = sequence->GetSortKey();
  TaskTraits traits(sequence->PeekTask()->traits);

  // Update the priority of |traits| so that the next task in |sequence| runs
  // with the highest priority in |sequence| as opposed to the next task's
  // specific priority.
  traits.WithPriority(sort_key.priority());

  GetWorkerPoolForTraits(traits)->ReEnqueueSequence(std::move(sequence),
                                                    sort_key);
}

void TaskSchedulerImpl::OnDelayedRunTimeUpdated() {
  service_thread_->WakeUp();
}

}  // namespace internal
}  // namespace base
