// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/shared_memory.h"

#include <mach/mach_vm.h>

#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/logging.h"
#include "base/mac/foundation_util.h"
#include "base/mac/mac_util.h"
#include "base/mac/scoped_mach_vm.h"
#if 0
#include "base/metrics/field_trial.h"
#endif
#include "base/metrics/histogram_macros.h"
#if 0
#include "base/process/process_metrics.h"
#include "base/profiler/scoped_tracker.h"
#endif
#include "base/scoped_generic.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"

namespace base {

namespace {

// Returns whether the operation succeeded.
// |new_handle| is an output variable, populated on success. The caller takes
// ownership of the underlying memory object.
// |handle| is the handle to copy.
// If |handle| is already mapped, |mapped_addr| is its mapped location.
// Otherwise, |mapped_addr| should be |nullptr|.
bool MakeMachSharedMemoryHandleReadOnly(SharedMemoryHandle* new_handle,
                                        SharedMemoryHandle handle,
                                        void* mapped_addr) {
  if (!handle.IsValid())
    return false;

  size_t size;
  CHECK(handle.GetSize(&size));

  // Map if necessary.
  void* temp_addr = mapped_addr;
  base::mac::ScopedMachVM scoper;
  if (!temp_addr) {
    // Intentionally lower current prot and max prot to |VM_PROT_READ|.
    kern_return_t kr = mach_vm_map(
        mach_task_self(), reinterpret_cast<mach_vm_address_t*>(&temp_addr),
        size, 0, VM_FLAGS_ANYWHERE, handle.GetMemoryObject(), 0, FALSE,
        VM_PROT_READ, VM_PROT_READ, VM_INHERIT_NONE);
    if (kr != KERN_SUCCESS)
      return false;
    scoper.reset(reinterpret_cast<vm_address_t>(temp_addr),
                 mach_vm_round_page(size));
  }

  // Make new memory object.
  mach_port_t named_right;
  kern_return_t kr = mach_make_memory_entry_64(
      mach_task_self(), reinterpret_cast<memory_object_size_t*>(&size),
      reinterpret_cast<memory_object_offset_t>(temp_addr), VM_PROT_READ,
      &named_right, MACH_PORT_NULL);
  if (kr != KERN_SUCCESS)
    return false;

  *new_handle = SharedMemoryHandle(named_right, size, base::GetCurrentProcId());
  return true;
}

}  // namespace

SharedMemoryCreateOptions::SharedMemoryCreateOptions()
    : size(0),
      executable(false),
      share_read_only(false) {}

SharedMemory::SharedMemory()
    : mapped_size_(0), memory_(NULL), read_only_(false), requested_size_(0) {}

SharedMemory::SharedMemory(const SharedMemoryHandle& handle, bool read_only)
    : shm_(handle),
      mapped_size_(0),
      memory_(NULL),
      read_only_(read_only),
      requested_size_(0) {}

SharedMemory::~SharedMemory() {
  Unmap();
  Close();
}

// static
bool SharedMemory::IsHandleValid(const SharedMemoryHandle& handle) {
  return handle.IsValid();
}

// static
SharedMemoryHandle SharedMemory::NULLHandle() {
  return SharedMemoryHandle();
}

// static
void SharedMemory::CloseHandle(const SharedMemoryHandle& handle) {
  handle.Close();
}

// static
size_t SharedMemory::GetHandleLimit() {
  // This should be effectively unlimited on OS X.
  return 10000;
}

// static
SharedMemoryHandle SharedMemory::DuplicateHandle(
    const SharedMemoryHandle& handle) {
  return handle.Duplicate();
}

bool SharedMemory::CreateAndMapAnonymous(size_t size) {
  return CreateAnonymous(size) && Map(size);
}

// static
bool SharedMemory::GetSizeFromSharedMemoryHandle(
    const SharedMemoryHandle& handle,
    size_t* size) {
  return handle.GetSize(size);
}

// Chromium mostly only uses the unique/private shmem as specified by
// "name == L"". The exception is in the StatsTable.
bool SharedMemory::Create(const SharedMemoryCreateOptions& options) {
  // TODO(erikchen): Remove ScopedTracker below once http://crbug.com/466437
  // is fixed.
#if 0
  tracked_objects::ScopedTracker tracking_profile1(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "466437 SharedMemory::Create::Start"));
#endif
  DCHECK(!shm_.IsValid());
  if (options.size == 0) return false;

  if (options.size > static_cast<size_t>(std::numeric_limits<int>::max()))
    return false;

  shm_ = SharedMemoryHandle(options.size);
  requested_size_ = options.size;
  return shm_.IsValid();
}

bool SharedMemory::MapAt(off_t offset, size_t bytes) {
  if (!shm_.IsValid())
    return false;
  if (bytes > static_cast<size_t>(std::numeric_limits<int>::max()))
    return false;
  if (memory_)
    return false;

  bool success = shm_.MapAt(offset, bytes, &memory_, read_only_);
  if (success) {
    mapped_size_ = bytes;
    DCHECK_EQ(0U, reinterpret_cast<uintptr_t>(memory_) &
                      (SharedMemory::MAP_MINIMUM_ALIGNMENT - 1));
  } else {
    memory_ = NULL;
  }

  return success;
}

bool SharedMemory::Unmap() {
  if (memory_ == NULL)
    return false;

  mach_vm_deallocate(mach_task_self(),
                     reinterpret_cast<mach_vm_address_t>(memory_),
                     mapped_size_);
  memory_ = NULL;
  mapped_size_ = 0;
  return true;
}

SharedMemoryHandle SharedMemory::handle() const {
  return shm_;
}

void SharedMemory::Close() {
  shm_.Close();
  shm_ = SharedMemoryHandle();
}

bool SharedMemory::ShareToProcessCommon(ProcessHandle process,
                                        SharedMemoryHandle* new_handle,
                                        bool close_self,
                                        ShareMode share_mode) {
  DCHECK(shm_.IsValid());

  bool success = false;
  switch (share_mode) {
    case SHARE_CURRENT_MODE:
      *new_handle = shm_.Duplicate();
      success = true;
      break;
    case SHARE_READONLY:
      success = MakeMachSharedMemoryHandleReadOnly(new_handle, shm_, memory_);
      break;
  }

  if (success)
    new_handle->SetOwnershipPassesToIPC(true);

  if (close_self) {
    Unmap();
    Close();
  }

  return success;
}

}  // namespace base
