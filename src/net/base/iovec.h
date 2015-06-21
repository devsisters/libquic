// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IOVEC_H_
#define NET_BASE_IOVEC_H_

#if defined(OS_POSIX)
#include <sys/uio.h>
#else
/* Structure for scatter/gather I/O.  */
struct iovec {
  void* iov_base;  /* Pointer to data.  */
  size_t iov_len;  /* Length of data.  */
};
#endif  // defined(OS_LINUX)

#endif  // NET_BASE_IOVEC_H_
