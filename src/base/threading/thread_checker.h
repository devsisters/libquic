// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_THREADING_THREAD_CHECKER_H_
#define BASE_THREADING_THREAD_CHECKER_H_

#include "base/logging.h"
#include "base/threading/thread_checker_impl.h"

namespace base {

// Do nothing implementation, for use in release mode.
//
// Note: You should almost always use the ThreadChecker class to get the
// right version for your build configuration.
class ThreadCheckerDoNothing {
 public:
  bool CalledOnValidThread() const WARN_UNUSED_RESULT {
    return true;
  }

  void DetachFromThread() {}
};

// ThreadChecker is a helper class used to help verify that some methods of a
// class are called from the same thread. It provides identical functionality to
// base::NonThreadSafe, but it is meant to be held as a member variable, rather
// than inherited from base::NonThreadSafe.
//
// While inheriting from base::NonThreadSafe may give a clear indication about
// the thread-safety of a class, it may also lead to violations of the style
// guide with regard to multiple inheritance. The choice between having a
// ThreadChecker member and inheriting from base::NonThreadSafe should be based
// on whether:
//  - Derived classes need to know the thread they belong to, as opposed to
//    having that functionality fully encapsulated in the base class.
//  - Derived classes should be able to reassign the base class to another
//    thread, via DetachFromThread.
//
// If neither of these are true, then having a ThreadChecker member and calling
// CalledOnValidThread is the preferable solution.
//
// Example:
// class MyClass {
//  public:
//   void Foo() {
//     DCHECK(thread_checker_.CalledOnValidThread());
//     ... (do stuff) ...
//   }
//
//  private:
//   ThreadChecker thread_checker_;
// }
//
// Note that, when enabled, CalledOnValidThread() returns false when called from
// tasks posted to SingleThreadTaskRunners bound to different sequences, even if
// the tasks happen to run on the same thread (e.g. two independent TaskRunners
// with ExecutionMode::SINGLE_THREADED on the TaskScheduler that happen to share
// a thread).
//
// In Release mode, CalledOnValidThread will always return true.
#if DCHECK_IS_ON()
class ThreadChecker : public ThreadCheckerImpl {
};
#else
class ThreadChecker : public ThreadCheckerDoNothing {
};
#endif  // DCHECK_IS_ON()

}  // namespace base

#endif  // BASE_THREADING_THREAD_CHECKER_H_
