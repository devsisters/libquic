// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_CPP_SYMBOLS_H_
#error This header is meant to be included only once by allocator_shim.cc
#endif
#define BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_CPP_SYMBOLS_H_

// Alias the default new/delete C++ symbols to the shim entry points.
// This file is strongly inspired by tcmalloc's libc_override_redefine.h.

#include <new>

#include "base/allocator/allocator_shim_internals.h"

SHIM_ALWAYS_EXPORT void* operator new(size_t size)
    SHIM_ALIAS_SYMBOL(ShimCppNew);

SHIM_ALWAYS_EXPORT void operator delete(void* p) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppDelete);

SHIM_ALWAYS_EXPORT void* operator new[](size_t size)
    SHIM_ALIAS_SYMBOL(ShimCppNew);

SHIM_ALWAYS_EXPORT void operator delete[](void* p) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppDelete);

SHIM_ALWAYS_EXPORT void* operator new(size_t size,
                                      const std::nothrow_t&) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppNew);

SHIM_ALWAYS_EXPORT void* operator new[](size_t size,
                                        const std::nothrow_t&) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppNew);

SHIM_ALWAYS_EXPORT void operator delete(void* p, const std::nothrow_t&) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppDelete);

SHIM_ALWAYS_EXPORT void operator delete[](void* p,
                                          const std::nothrow_t&) __THROW
    SHIM_ALIAS_SYMBOL(ShimCppDelete);
