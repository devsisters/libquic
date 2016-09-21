// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/task_scheduler/scheduler_worker_pool_impl.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "base/atomicops.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/lazy_instance.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram.h"
#include "base/sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/stringprintf.h"
#include "base/task_scheduler/delayed_task_manager.h"
#include "base/task_scheduler/task_tracker.h"
#include "base/threading/platform_thread.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_restrictions.h"
#include "base/time/time.h"

namespace base {
namespace internal {

namespace {

constexpr char kPoolNameSuffix[] = "Pool";
constexpr char kDetachDurationHistogramPrefix[] =
    "TaskScheduler.DetachDuration.";
constexpr char kTaskLatencyHistogramPrefix[] = "TaskScheduler.TaskLatency.";

// SchedulerWorker that owns the current thread, if any.
LazyInstance<ThreadLocalPointer<const SchedulerWorker>>::Leaky
    tls_current_worker = LAZY_INSTANCE_INITIALIZER;

// SchedulerWorkerPool that owns the current thread, if any.
LazyInstance<ThreadLocalPointer<const SchedulerWorkerPool>>::Leaky
    tls_current_worker_pool = LAZY_INSTANCE_INITIALIZER;

// A task runner that runs tasks with the PARALLEL ExecutionMode.
class SchedulerParallelTaskRunner : public TaskRunner {
 public:
  // Constructs a SchedulerParallelTaskRunner which can be used to post tasks so
  // long as |worker_pool| is alive.
  // TODO(robliao): Find a concrete way to manage |worker_pool|'s memory.
  SchedulerParallelTaskRunner(const TaskTraits& traits,
                              SchedulerWorkerPool* worker_pool)
      : traits_(traits), worker_pool_(worker_pool) {
    DCHECK(worker_pool_);
  }

  // TaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       const Closure& closure,
                       TimeDelta delay) override {
    // Post the task as part of a one-off single-task Sequence.
    return worker_pool_->PostTaskWithSequence(
        MakeUnique<Task>(from_here, closure, traits_, delay),
        make_scoped_refptr(new Sequence), nullptr);
  }

  bool RunsTasksOnCurrentThread() const override {
    return tls_current_worker_pool.Get().Get() == worker_pool_;
  }

 private:
  ~SchedulerParallelTaskRunner() override = default;

  const TaskTraits traits_;
  SchedulerWorkerPool* const worker_pool_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerParallelTaskRunner);
};

// A task runner that runs tasks with the SEQUENCED ExecutionMode.
class SchedulerSequencedTaskRunner : public SequencedTaskRunner {
 public:
  // Constructs a SchedulerSequencedTaskRunner which can be used to post tasks
  // so long as |worker_pool| is alive.
  // TODO(robliao): Find a concrete way to manage |worker_pool|'s memory.
  SchedulerSequencedTaskRunner(const TaskTraits& traits,
                               SchedulerWorkerPool* worker_pool)
      : traits_(traits), worker_pool_(worker_pool) {
    DCHECK(worker_pool_);
  }

  // SequencedTaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       const Closure& closure,
                       TimeDelta delay) override {
    std::unique_ptr<Task> task(new Task(from_here, closure, traits_, delay));
    task->sequenced_task_runner_ref = this;

    // Post the task as part of |sequence_|.
    return worker_pool_->PostTaskWithSequence(std::move(task), sequence_,
                                              nullptr);
  }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  const Closure& closure,
                                  base::TimeDelta delay) override {
    // Tasks are never nested within the task scheduler.
    return PostDelayedTask(from_here, closure, delay);
  }

  bool RunsTasksOnCurrentThread() const override {
    return tls_current_worker_pool.Get().Get() == worker_pool_;
  }

 private:
  ~SchedulerSequencedTaskRunner() override = default;

  // Sequence for all Tasks posted through this TaskRunner.
  const scoped_refptr<Sequence> sequence_ = new Sequence;

  const TaskTraits traits_;
  SchedulerWorkerPool* const worker_pool_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerSequencedTaskRunner);
};

HistogramBase* GetTaskLatencyHistogram(const std::string& pool_name,
                                       TaskPriority task_priority) {
  const char* task_priority_suffix = nullptr;
  switch (task_priority) {
    case TaskPriority::BACKGROUND:
      task_priority_suffix = ".BackgroundTaskPriority";
      break;
    case TaskPriority::USER_VISIBLE:
      task_priority_suffix = ".UserVisibleTaskPriority";
      break;
    case TaskPriority::USER_BLOCKING:
      task_priority_suffix = ".UserBlockingTaskPriority";
      break;
  }

  // Mimics the UMA_HISTOGRAM_TIMES macro.
  return Histogram::FactoryTimeGet(kTaskLatencyHistogramPrefix + pool_name +
                                       kPoolNameSuffix + task_priority_suffix,
                                   TimeDelta::FromMilliseconds(1),
                                   TimeDelta::FromSeconds(10), 50,
                                   HistogramBase::kUmaTargetedHistogramFlag);
}

// Only used in DCHECKs.
bool ContainsWorker(
    const std::vector<std::unique_ptr<SchedulerWorker>>& workers,
    const SchedulerWorker* worker) {
  auto it = std::find_if(workers.begin(), workers.end(),
      [worker](const std::unique_ptr<SchedulerWorker>& i) {
        return i.get() == worker;
      });
  return it != workers.end();
}

}  // namespace

// A task runner that runs tasks with the SINGLE_THREADED ExecutionMode.
class SchedulerWorkerPoolImpl::SchedulerSingleThreadTaskRunner :
    public SingleThreadTaskRunner {
 public:
  // Constructs a SchedulerSingleThreadTaskRunner which can be used to post
  // tasks so long as |worker_pool| and |worker| are alive.
  // TODO(robliao): Find a concrete way to manage the memory of |worker_pool|
  // and |worker|.
  SchedulerSingleThreadTaskRunner(const TaskTraits& traits,
                                  SchedulerWorkerPool* worker_pool,
                                  SchedulerWorker* worker);

  // SingleThreadTaskRunner:
  bool PostDelayedTask(const tracked_objects::Location& from_here,
                       const Closure& closure,
                       TimeDelta delay) override {
    std::unique_ptr<Task> task(new Task(from_here, closure, traits_, delay));
    task->single_thread_task_runner_ref = this;

    // Post the task to be executed by |worker_| as part of |sequence_|.
    return worker_pool_->PostTaskWithSequence(std::move(task), sequence_,
                                              worker_);
  }

  bool PostNonNestableDelayedTask(const tracked_objects::Location& from_here,
                                  const Closure& closure,
                                  base::TimeDelta delay) override {
    // Tasks are never nested within the task scheduler.
    return PostDelayedTask(from_here, closure, delay);
  }

  bool RunsTasksOnCurrentThread() const override {
    return tls_current_worker.Get().Get() == worker_;
  }

 private:
  ~SchedulerSingleThreadTaskRunner() override;

  // Sequence for all Tasks posted through this TaskRunner.
  const scoped_refptr<Sequence> sequence_ = new Sequence;

  const TaskTraits traits_;
  SchedulerWorkerPool* const worker_pool_;
  SchedulerWorker* const worker_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerSingleThreadTaskRunner);
};

class SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl
    : public SchedulerWorker::Delegate {
 public:
  // |outer| owns the worker for which this delegate is constructed.
  // |re_enqueue_sequence_callback| is invoked when ReEnqueueSequence() is
  // called with a non-single-threaded Sequence. |shared_priority_queue| is a
  // PriorityQueue whose transactions may overlap with the worker's
  // single-threaded PriorityQueue's transactions. |index| will be appended to
  // the pool name to label the underlying worker threads.
  SchedulerWorkerDelegateImpl(
      SchedulerWorkerPoolImpl* outer,
      const ReEnqueueSequenceCallback& re_enqueue_sequence_callback,
      const PriorityQueue* shared_priority_queue,
      int index);
  ~SchedulerWorkerDelegateImpl() override;

  PriorityQueue* single_threaded_priority_queue() {
    return &single_threaded_priority_queue_;
  }

  // SchedulerWorker::Delegate:
  void OnMainEntry(SchedulerWorker* worker,
                   const TimeDelta& detach_duration) override;
  scoped_refptr<Sequence> GetWork(SchedulerWorker* worker) override;
  void DidRunTask(const Task* task, const TimeDelta& task_latency) override;
  void ReEnqueueSequence(scoped_refptr<Sequence> sequence) override;
  TimeDelta GetSleepTimeout() override;
  bool CanDetach(SchedulerWorker* worker) override;

  void RegisterSingleThreadTaskRunner() {
    // No barrier as barriers only affect sequential consistency which is
    // irrelevant in a single variable use case (they don't force an immediate
    // flush anymore than atomics do by default).
    subtle::NoBarrier_AtomicIncrement(&num_single_threaded_runners_, 1);
  }

  void UnregisterSingleThreadTaskRunner() {
    subtle::NoBarrier_AtomicIncrement(&num_single_threaded_runners_, -1);
  }

 private:
  SchedulerWorkerPoolImpl* outer_;
  const ReEnqueueSequenceCallback re_enqueue_sequence_callback_;

  // Single-threaded PriorityQueue for the worker.
  PriorityQueue single_threaded_priority_queue_;

  // True if the last Sequence returned by GetWork() was extracted from
  // |single_threaded_priority_queue_|.
  bool last_sequence_is_single_threaded_ = false;

  // Time when GetWork() first returned nullptr.
  TimeTicks idle_start_time_;

  subtle::Atomic32 num_single_threaded_runners_ = 0;

  const int index_;

  DISALLOW_COPY_AND_ASSIGN(SchedulerWorkerDelegateImpl);
};

SchedulerWorkerPoolImpl::~SchedulerWorkerPoolImpl() {
  // SchedulerWorkerPool should never be deleted in production unless its
  // initialization failed.
  DCHECK(join_for_testing_returned_.IsSignaled() || workers_.empty());
}

// static
std::unique_ptr<SchedulerWorkerPoolImpl> SchedulerWorkerPoolImpl::Create(
    const SchedulerWorkerPoolParams& params,
    const ReEnqueueSequenceCallback& re_enqueue_sequence_callback,
    TaskTracker* task_tracker,
    DelayedTaskManager* delayed_task_manager) {
  std::unique_ptr<SchedulerWorkerPoolImpl> worker_pool(
      new SchedulerWorkerPoolImpl(params.name(),
                                  params.io_restriction(),
                                  params.suggested_reclaim_time(),
                                  task_tracker, delayed_task_manager));
  if (worker_pool->Initialize(params.priority_hint(), params.max_threads(),
                              re_enqueue_sequence_callback)) {
    return worker_pool;
  }
  return nullptr;
}

void SchedulerWorkerPoolImpl::WaitForAllWorkersIdleForTesting() {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  while (idle_workers_stack_.Size() < workers_.size())
    idle_workers_stack_cv_for_testing_->Wait();
}

void SchedulerWorkerPoolImpl::JoinForTesting() {
  DCHECK(!CanWorkerDetachForTesting() || suggested_reclaim_time_.is_max()) <<
      "Workers can detach during join.";
  for (const auto& worker : workers_)
    worker->JoinForTesting();

  DCHECK(!join_for_testing_returned_.IsSignaled());
  join_for_testing_returned_.Signal();
}

void SchedulerWorkerPoolImpl::DisallowWorkerDetachmentForTesting() {
  worker_detachment_disallowed_.Set();
}

scoped_refptr<TaskRunner> SchedulerWorkerPoolImpl::CreateTaskRunnerWithTraits(
    const TaskTraits& traits,
    ExecutionMode execution_mode) {
  switch (execution_mode) {
    case ExecutionMode::PARALLEL:
      return make_scoped_refptr(new SchedulerParallelTaskRunner(traits, this));

    case ExecutionMode::SEQUENCED:
      return make_scoped_refptr(new SchedulerSequencedTaskRunner(traits, this));

    case ExecutionMode::SINGLE_THREADED: {
      // TODO(fdoray): Find a way to take load into account when assigning a
      // SchedulerWorker to a SingleThreadTaskRunner. Also, this code
      // assumes that all SchedulerWorkers are alive. Eventually, we might
      // decide to tear down threads that haven't run tasks for a long time.
      size_t worker_index;
      {
        AutoSchedulerLock auto_lock(next_worker_index_lock_);
        worker_index = next_worker_index_;
        next_worker_index_ = (next_worker_index_ + 1) % workers_.size();
      }
      return make_scoped_refptr(new SchedulerSingleThreadTaskRunner(
          traits, this, workers_[worker_index].get()));
    }
  }

  NOTREACHED();
  return nullptr;
}

void SchedulerWorkerPoolImpl::ReEnqueueSequence(
    scoped_refptr<Sequence> sequence,
    const SequenceSortKey& sequence_sort_key) {
  shared_priority_queue_.BeginTransaction()->Push(std::move(sequence),
                                                  sequence_sort_key);

  // The thread calling this method just ran a Task from |sequence| and will
  // soon try to get another Sequence from which to run a Task. If the thread
  // belongs to this pool, it will get that Sequence from
  // |shared_priority_queue_|. When that's the case, there is no need to wake up
  // another worker after |sequence| is inserted in |shared_priority_queue_|. If
  // we did wake up another worker, we would waste resources by having more
  // workers trying to get a Sequence from |shared_priority_queue_| than the
  // number of Sequences in it.
  if (tls_current_worker_pool.Get().Get() != this)
    WakeUpOneWorker();
}

bool SchedulerWorkerPoolImpl::PostTaskWithSequence(
    std::unique_ptr<Task> task,
    scoped_refptr<Sequence> sequence,
    SchedulerWorker* worker) {
  DCHECK(task);
  DCHECK(sequence);
  DCHECK(!worker || ContainsWorker(workers_, worker));

  if (!task_tracker_->WillPostTask(task.get()))
    return false;

  if (task->delayed_run_time.is_null()) {
    PostTaskWithSequenceNow(std::move(task), std::move(sequence), worker);
  } else {
    delayed_task_manager_->AddDelayedTask(std::move(task), std::move(sequence),
                                          worker, this);
  }

  return true;
}

void SchedulerWorkerPoolImpl::PostTaskWithSequenceNow(
    std::unique_ptr<Task> task,
    scoped_refptr<Sequence> sequence,
    SchedulerWorker* worker) {
  DCHECK(task);
  DCHECK(sequence);
  DCHECK(!worker || ContainsWorker(workers_, worker));

  // Confirm that |task| is ready to run (its delayed run time is either null or
  // in the past).
  DCHECK_LE(task->delayed_run_time, delayed_task_manager_->Now());

  // Because |worker| belongs to this worker pool, we know that the type
  // of its delegate is SchedulerWorkerDelegateImpl.
  PriorityQueue* const priority_queue =
      worker
          ? static_cast<SchedulerWorkerDelegateImpl*>(worker->delegate())
                ->single_threaded_priority_queue()
          : &shared_priority_queue_;
  DCHECK(priority_queue);

  const bool sequence_was_empty = sequence->PushTask(std::move(task));
  if (sequence_was_empty) {
    // Insert |sequence| in |priority_queue| if it was empty before |task| was
    // inserted into it. Otherwise, one of these must be true:
    // - |sequence| is already in a PriorityQueue (not necessarily
    //   |shared_priority_queue_|), or,
    // - A worker is running a Task from |sequence|. It will insert |sequence|
    //   in a PriorityQueue once it's done running the Task.
    const auto sequence_sort_key = sequence->GetSortKey();
    priority_queue->BeginTransaction()->Push(std::move(sequence),
                                             sequence_sort_key);

    // Wake up a worker to process |sequence|.
    if (worker)
      worker->WakeUp();
    else
      WakeUpOneWorker();
  }
}

SchedulerWorkerPoolImpl::SchedulerSingleThreadTaskRunner::
    SchedulerSingleThreadTaskRunner(const TaskTraits& traits,
                                    SchedulerWorkerPool* worker_pool,
                                    SchedulerWorker* worker)
    : traits_(traits),
      worker_pool_(worker_pool),
      worker_(worker) {
  DCHECK(worker_pool_);
  DCHECK(worker_);
  static_cast<SchedulerWorkerDelegateImpl*>(worker_->delegate())->
      RegisterSingleThreadTaskRunner();
}

SchedulerWorkerPoolImpl::SchedulerSingleThreadTaskRunner::
    ~SchedulerSingleThreadTaskRunner() {
  static_cast<SchedulerWorkerDelegateImpl*>(worker_->delegate())->
      UnregisterSingleThreadTaskRunner();
}

SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    SchedulerWorkerDelegateImpl(
        SchedulerWorkerPoolImpl* outer,
        const ReEnqueueSequenceCallback& re_enqueue_sequence_callback,
        const PriorityQueue* shared_priority_queue,
        int index)
    : outer_(outer),
      re_enqueue_sequence_callback_(re_enqueue_sequence_callback),
      single_threaded_priority_queue_(shared_priority_queue),
      index_(index) {}

SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    ~SchedulerWorkerDelegateImpl() = default;

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::OnMainEntry(
    SchedulerWorker* worker,
    const TimeDelta& detach_duration) {
#if DCHECK_IS_ON()
  // Wait for |outer_->workers_created_| to avoid traversing
  // |outer_->workers_| while it is being filled by Initialize().
  outer_->workers_created_.Wait();
  DCHECK(ContainsWorker(outer_->workers_, worker));
#endif

  if (!detach_duration.is_max())
    outer_->detach_duration_histogram_->AddTime(detach_duration);

  PlatformThread::SetName(
      StringPrintf("TaskScheduler%sWorker%d", outer_->name_.c_str(), index_));

  DCHECK(!tls_current_worker.Get().Get());
  DCHECK(!tls_current_worker_pool.Get().Get());
  tls_current_worker.Get().Set(worker);
  tls_current_worker_pool.Get().Set(outer_);

  // New threads haven't run GetWork() yet, so reset the idle_start_time_.
  idle_start_time_ = TimeTicks();

  ThreadRestrictions::SetIOAllowed(
      outer_->io_restriction_ ==
          SchedulerWorkerPoolParams::IORestriction::ALLOWED);
}

scoped_refptr<Sequence>
SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::GetWork(
    SchedulerWorker* worker) {
  DCHECK(ContainsWorker(outer_->workers_, worker));

  scoped_refptr<Sequence> sequence;
  {
    std::unique_ptr<PriorityQueue::Transaction> shared_transaction(
        outer_->shared_priority_queue_.BeginTransaction());
    std::unique_ptr<PriorityQueue::Transaction> single_threaded_transaction(
        single_threaded_priority_queue_.BeginTransaction());

    if (shared_transaction->IsEmpty() &&
        single_threaded_transaction->IsEmpty()) {
      single_threaded_transaction.reset();

      // |shared_transaction| is kept alive while |worker| is added to
      // |idle_workers_stack_| to avoid this race:
      // 1. This thread creates a Transaction, finds |shared_priority_queue_|
      //    empty and ends the Transaction.
      // 2. Other thread creates a Transaction, inserts a Sequence into
      //    |shared_priority_queue_| and ends the Transaction. This can't happen
      //    if the Transaction of step 1 is still active because because there
      //    can only be one active Transaction per PriorityQueue at a time.
      // 3. Other thread calls WakeUpOneWorker(). No thread is woken up because
      //    |idle_workers_stack_| is empty.
      // 4. This thread adds itself to |idle_workers_stack_| and goes to sleep.
      //    No thread runs the Sequence inserted in step 2.
      outer_->AddToIdleWorkersStack(worker);
      if (idle_start_time_.is_null())
        idle_start_time_ = TimeTicks::Now();
      return nullptr;
    }

    // True if both PriorityQueues have Sequences and the Sequence at the top of
    // the shared PriorityQueue is more important.
    const bool shared_sequence_is_more_important =
        !shared_transaction->IsEmpty() &&
        !single_threaded_transaction->IsEmpty() &&
        shared_transaction->PeekSortKey() >
            single_threaded_transaction->PeekSortKey();

    if (single_threaded_transaction->IsEmpty() ||
        shared_sequence_is_more_important) {
      sequence = shared_transaction->PopSequence();
      last_sequence_is_single_threaded_ = false;
    } else {
      DCHECK(!single_threaded_transaction->IsEmpty());
      sequence = single_threaded_transaction->PopSequence();
      last_sequence_is_single_threaded_ = true;
    }
  }
  DCHECK(sequence);

  idle_start_time_ = TimeTicks();

  outer_->RemoveFromIdleWorkersStack(worker);
  return sequence;
}

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::DidRunTask(
    const Task* task,
    const TimeDelta& task_latency) {
  const int priority_index = static_cast<int>(task->traits.priority());

  // As explained in the header file, histograms are allocated on demand. It
  // doesn't matter if an element of |task_latency_histograms_| is set multiple
  // times since GetTaskLatencyHistogram() is idempotent. As explained in the
  // comment at the top of histogram_macros.h, barriers are required.
  HistogramBase* task_latency_histogram = reinterpret_cast<HistogramBase*>(
      subtle::Acquire_Load(&outer_->task_latency_histograms_[priority_index]));
  if (!task_latency_histogram) {
    task_latency_histogram =
        GetTaskLatencyHistogram(outer_->name_, task->traits.priority());
    subtle::Release_Store(
        &outer_->task_latency_histograms_[priority_index],
        reinterpret_cast<subtle::AtomicWord>(task_latency_histogram));
  }

  task_latency_histogram->AddTime(task_latency);
}

void SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    ReEnqueueSequence(scoped_refptr<Sequence> sequence) {
  if (last_sequence_is_single_threaded_) {
    // A single-threaded Sequence is always re-enqueued in the single-threaded
    // PriorityQueue from which it was extracted.
    const SequenceSortKey sequence_sort_key = sequence->GetSortKey();
    single_threaded_priority_queue_.BeginTransaction()->Push(
        std::move(sequence), sequence_sort_key);
  } else {
    // |re_enqueue_sequence_callback_| will determine in which PriorityQueue
    // |sequence| must be enqueued.
    re_enqueue_sequence_callback_.Run(std::move(sequence));
  }
}

TimeDelta SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::
    GetSleepTimeout() {
  return outer_->suggested_reclaim_time_;
}

bool SchedulerWorkerPoolImpl::SchedulerWorkerDelegateImpl::CanDetach(
    SchedulerWorker* worker) {
  // It's not an issue if |num_single_threaded_runners_| is incremented after
  // this because the newly created SingleThreadTaskRunner (from which no task
  // has run yet) will simply run all its tasks on the next physical thread
  // created by the worker.
  const bool can_detach =
      !idle_start_time_.is_null() &&
      (TimeTicks::Now() - idle_start_time_) > outer_->suggested_reclaim_time_ &&
      worker != outer_->PeekAtIdleWorkersStack() &&
      !subtle::NoBarrier_Load(&num_single_threaded_runners_) &&
      outer_->CanWorkerDetachForTesting();
  return can_detach;
}

SchedulerWorkerPoolImpl::SchedulerWorkerPoolImpl(
    StringPiece name,
    SchedulerWorkerPoolParams::IORestriction io_restriction,
    const TimeDelta& suggested_reclaim_time,
    TaskTracker* task_tracker,
    DelayedTaskManager* delayed_task_manager)
    : name_(name.as_string()),
      io_restriction_(io_restriction),
      suggested_reclaim_time_(suggested_reclaim_time),
      idle_workers_stack_lock_(shared_priority_queue_.container_lock()),
      idle_workers_stack_cv_for_testing_(
          idle_workers_stack_lock_.CreateConditionVariable()),
      join_for_testing_returned_(WaitableEvent::ResetPolicy::MANUAL,
                                 WaitableEvent::InitialState::NOT_SIGNALED),
#if DCHECK_IS_ON()
      workers_created_(WaitableEvent::ResetPolicy::MANUAL,
                       WaitableEvent::InitialState::NOT_SIGNALED),
#endif
      detach_duration_histogram_(Histogram::FactoryTimeGet(
          kDetachDurationHistogramPrefix + name_ + kPoolNameSuffix,
          TimeDelta::FromMilliseconds(1),
          TimeDelta::FromHours(1),
          50,
          HistogramBase::kUmaTargetedHistogramFlag)),
      task_tracker_(task_tracker),
      delayed_task_manager_(delayed_task_manager) {
  DCHECK(task_tracker_);
  DCHECK(delayed_task_manager_);
}

bool SchedulerWorkerPoolImpl::Initialize(
    ThreadPriority priority_hint,
    size_t max_threads,
    const ReEnqueueSequenceCallback& re_enqueue_sequence_callback) {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);

  DCHECK(workers_.empty());

  for (size_t i = 0; i < max_threads; ++i) {
    std::unique_ptr<SchedulerWorker> worker = SchedulerWorker::Create(
        priority_hint, MakeUnique<SchedulerWorkerDelegateImpl>(
                           this, re_enqueue_sequence_callback,
                           &shared_priority_queue_, static_cast<int>(i)),
        task_tracker_, i == 0 ? SchedulerWorker::InitialState::ALIVE
                              : SchedulerWorker::InitialState::DETACHED);
    if (!worker)
      break;
    idle_workers_stack_.Push(worker.get());
    workers_.push_back(std::move(worker));
  }

#if DCHECK_IS_ON()
  workers_created_.Signal();
#endif

  return !workers_.empty();
}

void SchedulerWorkerPoolImpl::WakeUpOneWorker() {
  SchedulerWorker* worker;
  {
    AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
    worker = idle_workers_stack_.Pop();
  }
  if (worker)
    worker->WakeUp();
}

void SchedulerWorkerPoolImpl::AddToIdleWorkersStack(
    SchedulerWorker* worker) {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  // Detachment may cause multiple attempts to add because the delegate cannot
  // determine who woke it up. As a result, when it wakes up, it may conclude
  // there's no work to be done and attempt to add itself to the idle stack
  // again.
  if (!idle_workers_stack_.Contains(worker))
    idle_workers_stack_.Push(worker);

  DCHECK_LE(idle_workers_stack_.Size(), workers_.size());

  if (idle_workers_stack_.Size() == workers_.size())
    idle_workers_stack_cv_for_testing_->Broadcast();
}

const SchedulerWorker* SchedulerWorkerPoolImpl::PeekAtIdleWorkersStack() const {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  return idle_workers_stack_.Peek();
}

void SchedulerWorkerPoolImpl::RemoveFromIdleWorkersStack(
    SchedulerWorker* worker) {
  AutoSchedulerLock auto_lock(idle_workers_stack_lock_);
  idle_workers_stack_.Remove(worker);
}

bool SchedulerWorkerPoolImpl::CanWorkerDetachForTesting() {
  return !worker_detachment_disallowed_.IsSet();
}

}  // namespace internal
}  // namespace base
