// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef NET_QUIC_QUIC_BUG_TRACKER_H_
#define NET_QUIC_QUIC_BUG_TRACKER_H_

// For external QUIC, QUIC_BUG should be #defined to LOG(DFATAL) and
// QUIC_BUG_IF(condition) to LOG_IF(DFATAL, condition) as client-side log rate
// limiting is less important and chrome doesn't LOG_FIRST_N anyway.
#define QUIC_BUG LOG(DFATAL)
#define QUIC_BUG_IF(condition) LOG_IF(DFATAL, condition)

#endif  // NET_QUIC_QUIC_BUG_TRACKER_H_
