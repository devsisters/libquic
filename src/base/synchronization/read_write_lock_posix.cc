// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/synchronization/read_write_lock.h"

#include "base/logging.h"

namespace base {
namespace subtle {

ReadWriteLock::ReadWriteLock() : native_handle_(PTHREAD_RWLOCK_INITIALIZER) {}

ReadWriteLock::~ReadWriteLock() {
  int result = pthread_rwlock_destroy(&native_handle_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::ReadAcquire() {
  int result = pthread_rwlock_rdlock(&native_handle_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::ReadRelease() {
  int result = pthread_rwlock_unlock(&native_handle_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::WriteAcquire() {
  int result = pthread_rwlock_wrlock(&native_handle_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

void ReadWriteLock::WriteRelease() {
  int result = pthread_rwlock_unlock(&native_handle_);
  DCHECK_EQ(result, 0) << ". " << strerror(result);
}

}  // namespace subtle
}  // namespace base
