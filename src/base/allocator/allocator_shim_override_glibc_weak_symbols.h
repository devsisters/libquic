// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_GLIBC_WEAK_SYMBOLS_H_
#error This header is meant to be included only once by allocator_shim.cc
#endif
#define BASE_ALLOCATOR_ALLOCATOR_SHIM_OVERRIDE_GLIBC_WEAK_SYMBOLS_H_

// Alias the internal Glibc symbols to the shim entry points.
// This file is strongly inspired by tcmalloc's libc_override_glibc.h.
// Effectively this file does two things:
//  1) Re-define the  __malloc_hook & co symbols. Those symbols are defined as
//     weak in glibc and are meant to be defined strongly by client processes
//     to hook calls initiated from within glibc.
//  2) Re-define Glibc-specific symbols (__libc_malloc). The historical reason
//     is that in the past (in RedHat 9) we had instances of libraries that were
//     allocating via malloc() and freeing using __libc_free().
//     See tcmalloc's libc_override_glibc.h for more context.

#include <features.h>  // for __GLIBC__
#include <malloc.h>
#include <unistd.h>

#include <new>

#include "base/allocator/allocator_shim_internals.h"

// __MALLOC_HOOK_VOLATILE not defined in all Glibc headers.
#if !defined(__MALLOC_HOOK_VOLATILE)
#define MALLOC_HOOK_MAYBE_VOLATILE /**/
#else
#define MALLOC_HOOK_MAYBE_VOLATILE __MALLOC_HOOK_VOLATILE
#endif

extern "C" {

// 1) Re-define malloc_hook weak symbols.
namespace {

void* GlibcMallocHook(size_t size, const void* caller) {
  return ShimMalloc(size);
}

void* GlibcReallocHook(void* ptr, size_t size, const void* caller) {
  return ShimRealloc(ptr, size);
}

void GlibcFreeHook(void* ptr, const void* caller) {
  return ShimFree(ptr);
}

void* GlibcMemalignHook(size_t align, size_t size, const void* caller) {
  return ShimMemalign(align, size);
}

}  // namespace

SHIM_ALWAYS_EXPORT void* (*MALLOC_HOOK_MAYBE_VOLATILE __malloc_hook)(
    size_t,
    const void*) = &GlibcMallocHook;

SHIM_ALWAYS_EXPORT void* (*MALLOC_HOOK_MAYBE_VOLATILE __realloc_hook)(
    void*,
    size_t,
    const void*) = &GlibcReallocHook;

SHIM_ALWAYS_EXPORT void (*MALLOC_HOOK_MAYBE_VOLATILE __free_hook)(void*,
                                                                  const void*) =
    &GlibcFreeHook;

SHIM_ALWAYS_EXPORT void* (*MALLOC_HOOK_MAYBE_VOLATILE __memalign_hook)(
    size_t,
    size_t,
    const void*) = &GlibcMemalignHook;

// 2) Redefine libc symbols themselves.

SHIM_ALWAYS_EXPORT void* __libc_malloc(size_t size)
    SHIM_ALIAS_SYMBOL(ShimMalloc);

SHIM_ALWAYS_EXPORT void __libc_free(void* ptr) SHIM_ALIAS_SYMBOL(ShimFree);

SHIM_ALWAYS_EXPORT void* __libc_realloc(void* ptr, size_t size)
    SHIM_ALIAS_SYMBOL(ShimRealloc);

SHIM_ALWAYS_EXPORT void* __libc_calloc(size_t n, size_t size)
    SHIM_ALIAS_SYMBOL(ShimCalloc);

SHIM_ALWAYS_EXPORT void __libc_cfree(void* ptr) SHIM_ALIAS_SYMBOL(ShimFree);

SHIM_ALWAYS_EXPORT void* __libc_memalign(size_t align, size_t s)
    SHIM_ALIAS_SYMBOL(ShimMemalign);

SHIM_ALWAYS_EXPORT void* __libc_valloc(size_t size)
    SHIM_ALIAS_SYMBOL(ShimValloc);

SHIM_ALWAYS_EXPORT void* __libc_pvalloc(size_t size)
    SHIM_ALIAS_SYMBOL(ShimPvalloc);

SHIM_ALWAYS_EXPORT int __posix_memalign(void** r, size_t a, size_t s)
    SHIM_ALIAS_SYMBOL(ShimPosixMemalign);

}  // extern "C"

// Safety check.
#if !defined(__GLIBC__)
#error The current platform does not seem to use Glibc.
#endif
