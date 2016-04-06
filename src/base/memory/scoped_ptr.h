// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// scoped_ptr is just a type alias for std::unique_ptr. Mass conversion coming
// soon (stay tuned for the PSA!), but until then, please continue using
// scoped_ptr.

#ifndef BASE_MEMORY_SCOPED_PTR_H_
#define BASE_MEMORY_SCOPED_PTR_H_

#include <memory>

template <typename T, typename D = std::default_delete<T>>
using scoped_ptr = std::unique_ptr<T, D>;

// A function to convert T* into scoped_ptr<T>
// Doing e.g. make_scoped_ptr(new FooBarBaz<type>(arg)) is a shorter notation
// for scoped_ptr<FooBarBaz<type> >(new FooBarBaz<type>(arg))
template <typename T>
scoped_ptr<T> make_scoped_ptr(T* ptr) {
  return scoped_ptr<T>(ptr);
}

#endif  // BASE_MEMORY_SCOPED_PTR_H_
