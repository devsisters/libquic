// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains utility functions and classes that help the
// implementation, and management of the Callback objects.

#ifndef BASE_CALLBACK_INTERNAL_H_
#define BASE_CALLBACK_INTERNAL_H_

#include "base/atomic_ref_count.h"
#include "base/base_export.h"
#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"

namespace base {
namespace internal {
template <CopyMode copy_mode>
class CallbackBase;

// BindStateBase is used to provide an opaque handle that the Callback
// class can use to represent a function object with bound arguments.  It
// behaves as an existential type that is used by a corresponding
// DoInvoke function to perform the function execution.  This allows
// us to shield the Callback class from the types of the bound argument via
// "type erasure."
// At the base level, the only task is to add reference counting data. Don't use
// RefCountedThreadSafe since it requires the destructor to be a virtual method.
// Creating a vtable for every BindState template instantiation results in a lot
// of bloat. Its only task is to call the destructor which can be done with a
// function pointer.
class BindStateBase {
 protected:
  explicit BindStateBase(void (*destructor)(BindStateBase*))
      : ref_count_(0), destructor_(destructor) {}
  ~BindStateBase() = default;

 private:
  friend class scoped_refptr<BindStateBase>;
  template <CopyMode copy_mode>
  friend class CallbackBase;

  void AddRef();
  void Release();

  AtomicRefCount ref_count_;

  // Pointer to a function that will properly destroy |this|.
  void (*destructor_)(BindStateBase*);

  DISALLOW_COPY_AND_ASSIGN(BindStateBase);
};

// Holds the Callback methods that don't require specialization to reduce
// template bloat.
// CallbackBase<MoveOnly> is a direct base class of MoveOnly callbacks, and
// CallbackBase<Copyable> uses CallbackBase<MoveOnly> for its implementation.
template <>
class BASE_EXPORT CallbackBase<CopyMode::MoveOnly> {
 public:
  CallbackBase(CallbackBase&& c);
  CallbackBase& operator=(CallbackBase&& c);

  // Returns true if Callback is null (doesn't refer to anything).
  bool is_null() const { return bind_state_.get() == NULL; }

  // Returns the Callback into an uninitialized state.
  void Reset();

 protected:
  // In C++, it is safe to cast function pointers to function pointers of
  // another type. It is not okay to use void*. We create a InvokeFuncStorage
  // that that can store our function pointer, and then cast it back to
  // the original type on usage.
  using InvokeFuncStorage = void(*)();

  // Returns true if this callback equals |other|. |other| may be null.
  bool EqualsInternal(const CallbackBase& other) const;

  // Allow initializing of |bind_state_| via the constructor to avoid default
  // initialization of the scoped_refptr.  We do not also initialize
  // |polymorphic_invoke_| here because doing a normal assignment in the
  // derived Callback templates makes for much nicer compiler errors.
  explicit CallbackBase(BindStateBase* bind_state);

  // Force the destructor to be instantiated inside this translation unit so
  // that our subclasses will not get inlined versions.  Avoids more template
  // bloat.
  ~CallbackBase();

  scoped_refptr<BindStateBase> bind_state_;
  InvokeFuncStorage polymorphic_invoke_ = nullptr;
};

// CallbackBase<Copyable> is a direct base class of Copyable Callbacks.
template <>
class BASE_EXPORT CallbackBase<CopyMode::Copyable>
    : public CallbackBase<CopyMode::MoveOnly> {
 public:
  CallbackBase(const CallbackBase& c);
  CallbackBase(CallbackBase&& c);
  CallbackBase& operator=(const CallbackBase& c);
  CallbackBase& operator=(CallbackBase&& c);
 protected:
  explicit CallbackBase(BindStateBase* bind_state)
      : CallbackBase<CopyMode::MoveOnly>(bind_state) {}
  ~CallbackBase() {}
};

extern template class CallbackBase<CopyMode::MoveOnly>;
extern template class CallbackBase<CopyMode::Copyable>;

}  // namespace internal
}  // namespace base

#endif  // BASE_CALLBACK_INTERNAL_H_
