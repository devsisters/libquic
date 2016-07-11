// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_BIND_H_
#define BASE_BIND_H_

#include "base/bind_internal.h"

// -----------------------------------------------------------------------------
// Usage documentation
// -----------------------------------------------------------------------------
//
// See base/callback.h for documentation.
//
//
// -----------------------------------------------------------------------------
// Implementation notes
// -----------------------------------------------------------------------------
//
// If you're reading the implementation, before proceeding further, you should
// read the top comment of base/bind_internal.h for a definition of common
// terms and concepts.

namespace base {

template <typename Functor, typename... Args>
inline base::Callback<MakeUnboundRunType<Functor, Args...>> Bind(
    Functor&& functor,
    Args&&... args) {
  using BindState = internal::MakeBindStateType<Functor, Args...>;
  using UnboundRunType = MakeUnboundRunType<Functor, Args...>;
  using Invoker = internal::Invoker<BindState, UnboundRunType>;

  using CallbackType = Callback<UnboundRunType>;
  return CallbackType(new BindState(std::forward<Functor>(functor),
                                    std::forward<Args>(args)...),
                      &Invoker::Run);
}

}  // namespace base

#endif  // BASE_BIND_H_
