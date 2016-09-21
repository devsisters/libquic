// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/files/memory_mapped_file.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base/logging.h"
#include "base/threading/thread_restrictions.h"
#include "build/build_config.h"

namespace base {

MemoryMappedFile::MemoryMappedFile() : data_(NULL), length_(0) {
}

#if !defined(OS_NACL)
bool MemoryMappedFile::MapFileRegionToMemory(
    const MemoryMappedFile::Region& region,
    Access access) {
  ThreadRestrictions::AssertIOAllowed();

  off_t map_start = 0;
  size_t map_size = 0;
  int32_t data_offset = 0;

  if (region == MemoryMappedFile::Region::kWholeFile) {
    int64_t file_len = file_.GetLength();
    if (file_len == -1) {
      DPLOG(ERROR) << "fstat " << file_.GetPlatformFile();
      return false;
    }
    map_size = static_cast<size_t>(file_len);
    length_ = map_size;
  } else {
    // The region can be arbitrarily aligned. mmap, instead, requires both the
    // start and size to be page-aligned. Hence, we map here the page-aligned
    // outer region [|aligned_start|, |aligned_start| + |size|] which contains
    // |region| and then add up the |data_offset| displacement.
    int64_t aligned_start = 0;
    int64_t aligned_size = 0;
    CalculateVMAlignedBoundaries(region.offset,
                                 region.size,
                                 &aligned_start,
                                 &aligned_size,
                                 &data_offset);

    // Ensure that the casts in the mmap call below are sane.
    if (aligned_start < 0 || aligned_size < 0 ||
        aligned_start > std::numeric_limits<off_t>::max() ||
        static_cast<uint64_t>(aligned_size) >
            std::numeric_limits<size_t>::max() ||
        static_cast<uint64_t>(region.size) >
            std::numeric_limits<size_t>::max()) {
      DLOG(ERROR) << "Region bounds are not valid for mmap";
      return false;
    }

    map_start = static_cast<off_t>(aligned_start);
    map_size = static_cast<size_t>(aligned_size);
    length_ = static_cast<size_t>(region.size);
  }

  int flags = 0;
  switch (access) {
    case READ_ONLY:
      flags |= PROT_READ;
      break;
    case READ_WRITE:
      flags |= PROT_READ | PROT_WRITE;
      break;
    case READ_WRITE_EXTEND:
      // POSIX won't auto-extend the file when it is written so it must first
      // be explicitly extended to the maximum size. Zeros will fill the new
      // space.
      file_.SetLength(std::max(file_.GetLength(), region.offset + region.size));
      flags |= PROT_READ | PROT_WRITE;
      break;
  }
  data_ = static_cast<uint8_t*>(mmap(NULL, map_size, flags, MAP_SHARED,
                                     file_.GetPlatformFile(), map_start));
  if (data_ == MAP_FAILED) {
    DPLOG(ERROR) << "mmap " << file_.GetPlatformFile();
    return false;
  }

  data_ += data_offset;
  return true;
}
#endif

void MemoryMappedFile::CloseHandles() {
  ThreadRestrictions::AssertIOAllowed();

  if (data_ != NULL)
    munmap(data_, length_);
  file_.Close();

  data_ = NULL;
  length_ = 0;
}

}  // namespace base
