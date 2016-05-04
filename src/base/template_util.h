// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_TEMPLATE_UTIL_H_
#define BASE_TEMPLATE_UTIL_H_

#include <stddef.h>
#include <type_traits>
#include <utility>

#include "build/build_config.h"

namespace base {

template <class T> struct is_non_const_reference : std::false_type {};
template <class T> struct is_non_const_reference<T&> : std::true_type {};
template <class T> struct is_non_const_reference<const T&> : std::false_type {};

// is_assignable

namespace internal {

template <typename First, typename Second>
struct SelectSecond {
  using type = Second;
};

struct Any {
  Any(...);
};

// True case: If |Lvalue| can be assigned to from |Rvalue|, then the return
// value is a true_type.
template <class Lvalue, class Rvalue>
typename internal::SelectSecond<
    decltype((std::declval<Lvalue>() = std::declval<Rvalue>())),
    std::true_type>::type
IsAssignableTest(Lvalue&&, Rvalue&&);

// False case: Otherwise the return value is a false_type.
template <class Rvalue>
std::false_type IsAssignableTest(internal::Any, Rvalue&&);

// Default case: Neither Lvalue nor Rvalue is void. Uses IsAssignableTest to
// determine the type of IsAssignableImpl.
template <class Lvalue,
          class Rvalue,
          bool = std::is_void<Lvalue>::value || std::is_void<Rvalue>::value>
struct IsAssignableImpl
    : public std::common_type<decltype(
          internal::IsAssignableTest(std::declval<Lvalue>(),
                                     std::declval<Rvalue>()))>::type {};

// Void case: Either Lvalue or Rvalue is void. Then the type of IsAssignableTest
// is false_type.
template <class Lvalue, class Rvalue>
struct IsAssignableImpl<Lvalue, Rvalue, true> : public std::false_type {};

}  // namespace internal

// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class Lvalue, class Rvalue>
struct is_assignable : public internal::IsAssignableImpl<Lvalue, Rvalue> {};

// is_copy_assignable is true if a T const& is assignable to a T&.
// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class T>
struct is_copy_assignable
    : public is_assignable<typename std::add_lvalue_reference<T>::type,
                           typename std::add_lvalue_reference<
                               typename std::add_const<T>::type>::type> {};

// is_move_assignable is true if a T&& is assignable to a T&.
// TODO(crbug.com/554293): Remove this when all platforms have this in the std
// namespace.
template <class T>
struct is_move_assignable
    : public is_assignable<typename std::add_lvalue_reference<T>::type,
                           const typename std::add_rvalue_reference<T>::type> {
};

}  // namespace base

#endif  // BASE_TEMPLATE_UTIL_H_
