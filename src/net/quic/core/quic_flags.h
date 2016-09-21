// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FLAGS_H_
#define NET_QUIC_QUIC_FLAGS_H_

#include <stdint.h>

#include "net/base/net_export.h"

#define QUIC_FLAG(type, flag, value) NET_EXPORT_PRIVATE extern type flag;
#include "net/quic/core/quic_flags_list.h"
#undef QUIC_FLAG

#endif  // NET_QUIC_QUIC_FLAGS_H_
