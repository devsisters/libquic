// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEMPLATE_UTIL_H_
#define BASE_TEMPLATE_UTIL_H_

#include <type_traits>

#include "build/build_config.h"

namespace base {

template <class T> struct is_non_const_reference : std::false_type {};
template <class T> struct is_non_const_reference<T&> : std::true_type {};
template <class T> struct is_non_const_reference<const T&> : std::false_type {};

}  // namespace base

#endif  // BASE_TEMPLATE_UTIL_H_
