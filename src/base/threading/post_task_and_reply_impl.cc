// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/threading/post_task_and_reply_impl.h"

#include "base/bind.h"
#include "base/callback.h"
#include "base/debug/leak_annotations.h"
#include "base/logging.h"
#include "base/memory/ref_counted.h"
#include "base/sequence_checker.h"
#include "base/sequenced_task_runner.h"
#include "base/threading/sequenced_task_runner_handle.h"

namespace base {

namespace {

// This relay class remembers the sequence that it was created on, and ensures
// that both the |task| and |reply| Closures are deleted on this same sequence.
// Also, |task| is guaranteed to be deleted before |reply| is run or deleted.
//
// If RunReplyAndSelfDestruct() doesn't run because the originating execution
// context is no longer available, then the |task| and |reply| Closures are
// leaked. Leaking is considered preferable to having a thread-safetey
// violations caused by invoking the Closure destructor on the wrong sequence.
class PostTaskAndReplyRelay {
 public:
  PostTaskAndReplyRelay(const tracked_objects::Location& from_here,
                        const Closure& task,
                        const Closure& reply)
      : sequence_checker_(),
        from_here_(from_here),
        origin_task_runner_(SequencedTaskRunnerHandle::Get()),
        reply_(reply),
        task_(task) {}

  ~PostTaskAndReplyRelay() {
    DCHECK(sequence_checker_.CalledOnValidSequence());
    task_.Reset();
    reply_.Reset();
  }

  void RunTaskAndPostReply() {
    task_.Run();
    origin_task_runner_->PostTask(
        from_here_, Bind(&PostTaskAndReplyRelay::RunReplyAndSelfDestruct,
                         base::Unretained(this)));
  }

 private:
  void RunReplyAndSelfDestruct() {
    DCHECK(sequence_checker_.CalledOnValidSequence());

    // Force |task_| to be released before |reply_| is to ensure that no one
    // accidentally depends on |task_| keeping one of its arguments alive while
    // |reply_| is executing.
    task_.Reset();

    reply_.Run();

    // Cue mission impossible theme.
    delete this;
  }

  const SequenceChecker sequence_checker_;
  const tracked_objects::Location from_here_;
  const scoped_refptr<SequencedTaskRunner> origin_task_runner_;
  Closure reply_;
  Closure task_;
};

}  // namespace

namespace internal {

bool PostTaskAndReplyImpl::PostTaskAndReply(
    const tracked_objects::Location& from_here,
    const Closure& task,
    const Closure& reply) {
  DCHECK(!task.is_null()) << from_here.ToString();
  DCHECK(!reply.is_null()) << from_here.ToString();
  PostTaskAndReplyRelay* relay =
      new PostTaskAndReplyRelay(from_here, task, reply);
  // PostTaskAndReplyRelay self-destructs after executing |reply|. On the flip
  // side though, it is intentionally leaked if the |task| doesn't complete
  // before the origin sequence stops executing tasks. Annotate |relay| as leaky
  // to avoid having to suppress every callsite which happens to flakily trigger
  // this race.
  ANNOTATE_LEAKING_OBJECT_PTR(relay);
  if (!PostTask(from_here, Bind(&PostTaskAndReplyRelay::RunTaskAndPostReply,
                                Unretained(relay)))) {
    delete relay;
    return false;
  }

  return true;
}

}  // namespace internal

}  // namespace base
