// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_ALLOCATOR_ALLOCATOR_SHIM_INTERNALS_H_
#define BASE_ALLOCATOR_ALLOCATOR_SHIM_INTERNALS_H_

#if defined(__GNUC__)

#include <sys/cdefs.h>  // for __THROW

#ifndef __THROW  // Not a glibc system
#ifdef _NOEXCEPT  // LLVM libc++ uses noexcept instead
#define __THROW _NOEXCEPT
#else
#define __THROW
#endif  // !_NOEXCEPT
#endif

// Shim layer symbols need to be ALWAYS exported, regardless of component build.
#define SHIM_ALWAYS_EXPORT __attribute__((visibility("default")))

#define SHIM_ALIAS_SYMBOL(fn) __attribute__((alias(#fn)))

#endif  // __GNUC__

#endif  // BASE_ALLOCATOR_ALLOCATOR_SHIM_INTERNALS_H_
