// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory_handle.h"

#include <mach/mach_vm.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

#include "base/mac/mac_util.h"
#include "base/posix/eintr_wrapper.h"

namespace base {

SharedMemoryHandle::SharedMemoryHandle() {}

SharedMemoryHandle::SharedMemoryHandle(mach_vm_size_t size) {
  mach_port_t named_right;
  kern_return_t kr = mach_make_memory_entry_64(
      mach_task_self(),
      &size,
      0,  // Address.
      MAP_MEM_NAMED_CREATE | VM_PROT_READ | VM_PROT_WRITE,
      &named_right,
      MACH_PORT_NULL);  // Parent handle.
  if (kr != KERN_SUCCESS) {
    memory_object_ = MACH_PORT_NULL;
    return;
  }

  memory_object_ = named_right;
  size_ = size;
  pid_ = GetCurrentProcId();
  ownership_passes_to_ipc_ = false;
}

SharedMemoryHandle::SharedMemoryHandle(mach_port_t memory_object,
                                       mach_vm_size_t size,
                                       base::ProcessId pid)
    : memory_object_(memory_object),
      size_(size),
      pid_(pid),
      ownership_passes_to_ipc_(false) {}

SharedMemoryHandle::SharedMemoryHandle(const SharedMemoryHandle& handle) {
  CopyRelevantData(handle);
}

SharedMemoryHandle& SharedMemoryHandle::operator=(
    const SharedMemoryHandle& handle) {
  if (this == &handle)
    return *this;

  CopyRelevantData(handle);
  return *this;
}

SharedMemoryHandle SharedMemoryHandle::Duplicate() const {
  if (!IsValid())
    return SharedMemoryHandle(MACH_PORT_NULL, 0, 0);

  // Increment the ref count.
  kern_return_t kr = mach_port_mod_refs(mach_task_self(), memory_object_,
                                        MACH_PORT_RIGHT_SEND, 1);
  DCHECK_EQ(kr, KERN_SUCCESS);
  SharedMemoryHandle handle(*this);
  handle.SetOwnershipPassesToIPC(true);
  return handle;
}

bool SharedMemoryHandle::operator==(const SharedMemoryHandle& handle) const {
  if (!IsValid() && !handle.IsValid())
    return true;

  return memory_object_ == handle.memory_object_ && size_ == handle.size_ &&
         pid_ == handle.pid_;
}

bool SharedMemoryHandle::operator!=(const SharedMemoryHandle& handle) const {
  return !(*this == handle);
}

bool SharedMemoryHandle::IsValid() const {
  return memory_object_ != MACH_PORT_NULL;
}

mach_port_t SharedMemoryHandle::GetMemoryObject() const {
  return memory_object_;
}

bool SharedMemoryHandle::GetSize(size_t* size) const {
  if (!IsValid()) {
    *size = 0;
    return true;
  }

  *size = size_;
  return true;
}

bool SharedMemoryHandle::MapAt(off_t offset,
                               size_t bytes,
                               void** memory,
                               bool read_only) {
  DCHECK(IsValid());
  DCHECK_EQ(pid_, GetCurrentProcId());
  kern_return_t kr = mach_vm_map(
      mach_task_self(),
      reinterpret_cast<mach_vm_address_t*>(memory),  // Output parameter
      bytes,
      0,  // Alignment mask
      VM_FLAGS_ANYWHERE, memory_object_, offset,
      FALSE,                                           // Copy
      VM_PROT_READ | (read_only ? 0 : VM_PROT_WRITE),  // Current protection
      VM_PROT_WRITE | VM_PROT_READ | VM_PROT_IS_MASK,  // Maximum protection
      VM_INHERIT_NONE);
  return kr == KERN_SUCCESS;
}

void SharedMemoryHandle::Close() const {
  if (!IsValid())
    return;

  kern_return_t kr = mach_port_deallocate(mach_task_self(), memory_object_);
  if (kr != KERN_SUCCESS)
    DPLOG(ERROR) << "Error deallocating mach port: " << kr;
}

void SharedMemoryHandle::SetOwnershipPassesToIPC(bool ownership_passes) {
  ownership_passes_to_ipc_ = ownership_passes;
}

bool SharedMemoryHandle::OwnershipPassesToIPC() const {
  return ownership_passes_to_ipc_;
}

void SharedMemoryHandle::CopyRelevantData(const SharedMemoryHandle& handle) {
  memory_object_ = handle.memory_object_;
  size_ = handle.size_;
  pid_ = handle.pid_;
  ownership_passes_to_ipc_ = handle.ownership_passes_to_ipc_;
}

}  // namespace base
