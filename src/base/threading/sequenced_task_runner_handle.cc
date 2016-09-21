// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/sequenced_task_runner_handle.h"

#include <utility>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/threading/sequenced_worker_pool.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"

namespace base {

namespace {

base::LazyInstance<base::ThreadLocalPointer<SequencedTaskRunnerHandle>>::Leaky
    lazy_tls_ptr = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
scoped_refptr<SequencedTaskRunner> SequencedTaskRunnerHandle::Get() {
  // Return the registered SequencedTaskRunner, if any.
  const SequencedTaskRunnerHandle* handle = lazy_tls_ptr.Pointer()->Get();
  if (handle) {
    // Various modes of setting SequencedTaskRunnerHandle don't combine.
    DCHECK(!base::ThreadTaskRunnerHandle::IsSet());
    DCHECK(!SequencedWorkerPool::GetSequenceTokenForCurrentThread().IsValid());
    return handle->task_runner_;
  }

  // If we are on a worker thread for a SequencedBlockingPool that is running a
  // sequenced task, return a SequencedTaskRunner for it.
  scoped_refptr<base::SequencedWorkerPool> pool =
      SequencedWorkerPool::GetWorkerPoolForCurrentThread();
  if (pool) {
    SequencedWorkerPool::SequenceToken sequence_token =
        SequencedWorkerPool::GetSequenceTokenForCurrentThread();
    DCHECK(sequence_token.IsValid());
    DCHECK(pool->IsRunningSequenceOnCurrentThread(sequence_token));
    return pool->GetSequencedTaskRunner(sequence_token);
  }

  // Return the SingleThreadTaskRunner for the current thread otherwise.
  return base::ThreadTaskRunnerHandle::Get();
}

// static
bool SequencedTaskRunnerHandle::IsSet() {
  return lazy_tls_ptr.Pointer()->Get() ||
         SequencedWorkerPool::GetSequenceTokenForCurrentThread().IsValid() ||
         base::ThreadTaskRunnerHandle::IsSet();
}

SequencedTaskRunnerHandle::SequencedTaskRunnerHandle(
    scoped_refptr<SequencedTaskRunner> task_runner)
    : task_runner_(std::move(task_runner)) {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());
  DCHECK(!SequencedTaskRunnerHandle::IsSet());
  lazy_tls_ptr.Pointer()->Set(this);
}

SequencedTaskRunnerHandle::~SequencedTaskRunnerHandle() {
  DCHECK(task_runner_->RunsTasksOnCurrentThread());
  DCHECK_EQ(lazy_tls_ptr.Pointer()->Get(), this);
  lazy_tls_ptr.Pointer()->Set(nullptr);
}

}  // namespace base
