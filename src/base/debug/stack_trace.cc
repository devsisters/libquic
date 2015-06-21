// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/debug/stack_trace.h"

#include "base/basictypes.h"

#include <string.h>

#include <algorithm>
#include <sstream>
#include <ostream>

namespace base {
namespace debug {

StackTrace::StackTrace() {
}

StackTrace::StackTrace(const void* const* trace, size_t count) {
}

StackTrace::~StackTrace() {
}

void StackTrace::OutputToStream(std::ostream* os) const {
}

const void *const *StackTrace::Addresses(size_t* count) const {
  return NULL;
}

std::string StackTrace::ToString() const {
  return "";
}

}  // namespace debug
}  // namespace base
