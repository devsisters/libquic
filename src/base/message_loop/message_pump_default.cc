// Copyright (c) 2006-2008 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/message_loop/message_pump_default.h"

#include <algorithm>

#include "base/logging.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"

#if defined(OS_MACOSX)
#include "base/mac/scoped_nsautorelease_pool.h"
#endif

namespace base {

MessagePumpDefault::MessagePumpDefault()
    : keep_running_(true),
      event_(WaitableEvent::ResetPolicy::AUTOMATIC,
             WaitableEvent::InitialState::NOT_SIGNALED) {}

MessagePumpDefault::~MessagePumpDefault() {
}

void MessagePumpDefault::Run(Delegate* delegate) {
  DCHECK(keep_running_) << "Quit must have been called outside of Run!";

  for (;;) {
#if defined(OS_MACOSX)
    mac::ScopedNSAutoreleasePool autorelease_pool;
#endif

    bool did_work = delegate->DoWork();
    if (!keep_running_)
      break;

    did_work |= delegate->DoDelayedWork(&delayed_work_time_);
    if (!keep_running_)
      break;

    if (did_work)
      continue;

    did_work = delegate->DoIdleWork();
    if (!keep_running_)
      break;

    if (did_work)
      continue;

    ThreadRestrictions::ScopedAllowWait allow_wait;
    if (delayed_work_time_.is_null()) {
      event_.Wait();
    } else {
      TimeDelta delay = delayed_work_time_ - TimeTicks::Now();
      if (delay > TimeDelta()) {
#if defined(OS_WIN)
        // TODO(stanisc): crbug.com/623223: Consider moving the OS_WIN specific
        // logic into TimedWait implementation in waitable_event_win.cc.

        // crbug.com/487724: on Windows, waiting for less than 1 ms results in
        // returning from TimedWait promptly and spinning
        // MessagePumpDefault::Run loop for up to 1 ms - until it is time to
        // run a delayed task. |min_delay| is the minimum possible wait to
        // to avoid the spinning.
        constexpr TimeDelta min_delay = TimeDelta::FromMilliseconds(1);
        do {
          delay = std::max(delay, min_delay);
          if (event_.TimedWait(delay))
            break;

          // TimedWait can time out earlier than the specified |delay| on
          // Windows. It doesn't make sense to run the outer loop in that case
          // because there isn't going to be any new work. It is less overhead
          // to just go back to wait.
          // In practice this inner wait loop might have up to 3 iterations.
          delay = delayed_work_time_ - TimeTicks::Now();
        } while (delay > TimeDelta());
#else
        event_.TimedWait(delay);
#endif
      } else {
        // It looks like delayed_work_time_ indicates a time in the past, so we
        // need to call DoDelayedWork now.
        delayed_work_time_ = TimeTicks();
      }
    }
    // Since event_ is auto-reset, we don't need to do anything special here
    // other than service each delegate method.
  }

  keep_running_ = true;
}

void MessagePumpDefault::Quit() {
  keep_running_ = false;
}

void MessagePumpDefault::ScheduleWork() {
  // Since this can be called on any thread, we need to ensure that our Run
  // loop wakes up.
  event_.Signal();
}

void MessagePumpDefault::ScheduleDelayedWork(
    const TimeTicks& delayed_work_time) {
  // We know that we can't be blocked on Wait right now since this method can
  // only be called on the same thread as Run, so we only need to update our
  // record of how long to sleep when we do sleep.
  delayed_work_time_ = delayed_work_time;
}

}  // namespace base
