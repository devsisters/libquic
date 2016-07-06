// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/scoped_file.h"

#include "base/logging.h"
#include "build/build_config.h"

#if defined(OS_POSIX)
#include <errno.h>
#include <unistd.h>

#include "base/debug/alias.h"
#include "base/posix/eintr_wrapper.h"
#endif

namespace base {
namespace internal {

#if defined(OS_POSIX)

// static
void ScopedFDCloseTraits::Free(int fd) {
  // It's important to crash here.
  // There are security implications to not closing a file descriptor
  // properly. As file descriptors are "capabilities", keeping them open
  // would make the current process keep access to a resource. Much of
  // Chrome relies on being able to "drop" such access.
  // It's especially problematic on Linux with the setuid sandbox, where
  // a single open directory would bypass the entire security model.
  int ret = IGNORE_EINTR(close(fd));

  // TODO(davidben): Remove this once it's been determined whether
  // https://crbug.com/603354 is caused by EBADF or a network filesystem
  // returning some other error.
  int close_errno = errno;
  base::debug::Alias(&close_errno);

  PCHECK(0 == ret);
}

#endif  // OS_POSIX

}  // namespace internal
}  // namespace base
