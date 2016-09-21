// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FLAGS_H_
#define NET_SPDY_SPDY_FLAGS_H_

#include "net/base/net_export.h"

NET_EXPORT_PRIVATE extern bool FLAGS_use_nested_spdy_framer_decoder;
NET_EXPORT_PRIVATE extern bool
    FLAGS_chromium_http2_flag_spdy_framer_use_new_methods4;
NET_EXPORT_PRIVATE extern bool
    FLAGS_chromium_http2_flag_use_new_spdy_header_block_header_joining;

#endif  // NET_SPDY_SPDY_FLAGS_H_
