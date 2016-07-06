// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FLAGS_H_
#define NET_SPDY_SPDY_FLAGS_H_

#include "net/base/net_export.h"

NET_EXPORT_PRIVATE extern bool
    FLAGS_chromium_http2_flag_remove_hpack_decode_buffer_size_limit;
NET_EXPORT_PRIVATE extern bool FLAGS_use_nested_spdy_framer_decoder;
NET_EXPORT_PRIVATE extern bool FLAGS_chromium_http2_flag_enforce_max_frame_size;

#endif  // NET_SPDY_SPDY_FLAGS_H_
