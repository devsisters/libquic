// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/memory_mapped_file.h"

#include <utility>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/sys_info.h"
#include "build/build_config.h"

namespace base {

const MemoryMappedFile::Region MemoryMappedFile::Region::kWholeFile = {0, 0};

bool MemoryMappedFile::Region::operator==(
    const MemoryMappedFile::Region& other) const {
  return other.offset == offset && other.size == size;
}

bool MemoryMappedFile::Region::operator!=(
    const MemoryMappedFile::Region& other) const {
  return other.offset != offset || other.size != size;
}

MemoryMappedFile::~MemoryMappedFile() {
  CloseHandles();
}

#if !defined(OS_NACL)
bool MemoryMappedFile::Initialize(const FilePath& file_name) {
  if (IsValid())
    return false;

  file_.Initialize(file_name, File::FLAG_OPEN | File::FLAG_READ);

  if (!file_.IsValid()) {
    DLOG(ERROR) << "Couldn't open " << file_name.AsUTF8Unsafe();
    return false;
  }

  if (!MapFileRegionToMemory(Region::kWholeFile)) {
    CloseHandles();
    return false;
  }

  return true;
}

bool MemoryMappedFile::Initialize(File file) {
  return Initialize(std::move(file), Region::kWholeFile);
}

bool MemoryMappedFile::Initialize(File file, const Region& region) {
  if (IsValid())
    return false;

  if (region != Region::kWholeFile) {
    DCHECK_GE(region.offset, 0);
    DCHECK_GT(region.size, 0);
  }

  file_ = std::move(file);

  if (!MapFileRegionToMemory(region)) {
    CloseHandles();
    return false;
  }

  return true;
}

bool MemoryMappedFile::IsValid() const {
  return data_ != NULL;
}

// static
void MemoryMappedFile::CalculateVMAlignedBoundaries(int64_t start,
                                                    int64_t size,
                                                    int64_t* aligned_start,
                                                    int64_t* aligned_size,
                                                    int32_t* offset) {
  // Sadly, on Windows, the mmap alignment is not just equal to the page size.
  const int64_t mask =
      static_cast<int64_t>(SysInfo::VMAllocationGranularity()) - 1;
  DCHECK_LT(mask, std::numeric_limits<int32_t>::max());
  *offset = start & mask;
  *aligned_start = start & ~mask;
  *aligned_size = (size + *offset + mask) & ~mask;
}
#endif

}  // namespace base
