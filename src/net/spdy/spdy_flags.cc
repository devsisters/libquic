// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_flags.h"

// Use NestedSpdyFramerDecoder.
bool FLAGS_use_nested_spdy_framer_decoder = false;

// If true, SpdyFramer uses the new visitor methods OnHeaderFrameStart and
// OnHeaderFrameEnd.  Fourth attempt.
bool FLAGS_chromium_http2_flag_spdy_framer_use_new_methods4 = true;

// Use SpdyHeaderBlock::AppendValueOrAddHeader when adding to headers.
bool FLAGS_chromium_http2_flag_use_new_spdy_header_block_header_joining = true;
