// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_SYNCHRONIZATION_READ_WRITE_LOCK_H_
#define BASE_SYNCHRONIZATION_READ_WRITE_LOCK_H_

#include "base/base_export.h"
#include "base/macros.h"
#include "build/build_config.h"

#if defined(OS_NACL)
#include "base/synchronization/lock.h"
#endif

#if defined(OS_WIN)
#include <windows.h>
#elif defined(OS_POSIX)
#include <pthread.h>
#else
#  error No reader-writer lock defined for this platform.
#endif

namespace base {
namespace subtle {

// An OS-independent wrapper around reader-writer locks. There's no magic here.
//
// You are strongly encouraged to use base::Lock instead of this, unless you
// can demonstrate contention and show that this would lead to an improvement.
// This lock does not make any guarantees of fairness, which can lead to writer
// starvation under certain access patterns. You should carefully consider your
// writer access patterns before using this lock.
class BASE_EXPORT ReadWriteLock {
 public:
  ReadWriteLock();
  ~ReadWriteLock();

  // Reader lock functions.
  void ReadAcquire();
  void ReadRelease();

  // Writer lock functions.
  void WriteAcquire();
  void WriteRelease();

 private:
#if defined(OS_WIN)
  using NativeHandle = SRWLOCK;
#elif defined(OS_NACL)
  using NativeHandle = Lock;
#elif defined(OS_POSIX)
  using NativeHandle = pthread_rwlock_t;
#endif

  NativeHandle native_handle_;

#if defined(OS_NACL)
  // Even though NaCl has a pthread_rwlock implementation, the build rules don't
  // make it universally available. So instead, implement a slower and trivial
  // reader-writer lock using a regular mutex.
  // TODO(amistry): Remove this and use the posix implementation when it's
  // available in all build configurations.
  uint32_t readers_ = 0;
  // base::Lock does checking to ensure the lock is acquired and released on the
  // same thread. This is not the case for this lock, so use pthread mutexes
  // directly here.
  pthread_mutex_t writer_lock_ = PTHREAD_MUTEX_INITIALIZER;
#endif

  DISALLOW_COPY_AND_ASSIGN(ReadWriteLock);
};

class AutoReadLock {
 public:
  explicit AutoReadLock(ReadWriteLock& lock) : lock_(lock) {
    lock_.ReadAcquire();
  }
  ~AutoReadLock() {
    lock_.ReadRelease();
  }

 private:
  ReadWriteLock& lock_;
  DISALLOW_COPY_AND_ASSIGN(AutoReadLock);
};

class AutoWriteLock {
 public:
  explicit AutoWriteLock(ReadWriteLock& lock) : lock_(lock) {
    lock_.WriteAcquire();
  }
  ~AutoWriteLock() {
    lock_.WriteRelease();
  }

 private:
  ReadWriteLock& lock_;
  DISALLOW_COPY_AND_ASSIGN(AutoWriteLock);
};

}  // namespace subtle
}  // namespace base

#endif  // BASE_SYNCHRONIZATION_READ_WRITE_LOCK_H_
