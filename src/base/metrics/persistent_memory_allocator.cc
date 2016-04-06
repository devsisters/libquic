// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/persistent_memory_allocator.h"

#include <assert.h>
#include <algorithm>

#if 0
#include "base/files/memory_mapped_file.h"
#endif
#include "base/logging.h"
#if 0
#include "base/memory/shared_memory.h"
#endif
#include "base/metrics/histogram_macros.h"

namespace {

// Required range of memory segment sizes. It has to fit in an unsigned 32-bit
// number and should be a power of 2 in order to accomodate almost any page
// size.
const uint32_t kSegmentMinSize = 1 << 10;  // 1 KiB
const uint32_t kSegmentMaxSize = 1 << 30;  // 1 GiB

// A constant (random) value placed in the shared metadata to identify
// an already initialized memory segment.
const uint32_t kGlobalCookie = 0x408305DC;

// The current version of the metadata. If updates are made that change
// the metadata, the version number can be queried to operate in a backward-
// compatible manner until the memory segment is completely re-initalized.
const uint32_t kGlobalVersion = 1;

// Constant values placed in the block headers to indicate its state.
const uint32_t kBlockCookieFree = 0;
const uint32_t kBlockCookieQueue = 1;
const uint32_t kBlockCookieWasted = (uint32_t)-1;
const uint32_t kBlockCookieAllocated = 0xC8799269;

// TODO(bcwhite): When acceptable, consider moving flags to std::atomic<char>
// types rather than combined bitfield.

// Flags stored in the flags_ field of the SharedMetaData structure below.
enum : int {
  kFlagCorrupt = 1 << 0,
  kFlagFull    = 1 << 1
};

bool CheckFlag(const volatile std::atomic<uint32_t>* flags, int flag) {
  uint32_t loaded_flags = flags->load();
  return (loaded_flags & flag) != 0;
}

void SetFlag(volatile std::atomic<uint32_t>* flags, int flag) {
  uint32_t loaded_flags = flags->load();
  for (;;) {
    uint32_t new_flags = (loaded_flags & ~flag) | flag;
    // In the failue case, actual "flags" value stored in loaded_flags.
    if (flags->compare_exchange_weak(loaded_flags, new_flags))
      break;
  }
}

}  // namespace

namespace base {

// All allocations and data-structures must be aligned to this byte boundary.
// Alignment as large as the physical bus between CPU and RAM is _required_
// for some architectures, is simply more efficient on other CPUs, and
// generally a Good Idea(tm) for all platforms as it reduces/eliminates the
// chance that a type will span cache lines. Alignment mustn't be less
// than 8 to ensure proper alignment for all types. The rest is a balance
// between reducing spans across multiple cache lines and wasted space spent
// padding out allocations. An alignment of 16 would ensure that the block
// header structure always sits in a single cache line. An average of about
// 1/2 this value will be wasted with every allocation.
const uint32_t PersistentMemoryAllocator::kAllocAlignment = 8;

// The block-header is placed at the top of every allocation within the
// segment to describe the data that follows it.
struct PersistentMemoryAllocator::BlockHeader {
  uint32_t size;       // Number of bytes in this block, including header.
  uint32_t cookie;     // Constant value indicating completed allocation.
  uint32_t type_id;    // A number provided by caller indicating data type.
  std::atomic<uint32_t> next;  // Pointer to the next block when iterating.
};

// The shared metadata exists once at the top of the memory segment to
// describe the state of the allocator to all processes.
struct PersistentMemoryAllocator::SharedMetadata {
  uint32_t cookie;     // Some value that indicates complete initialization.
  uint32_t size;       // Total size of memory segment.
  uint32_t page_size;  // Paging size within memory segment.
  uint32_t version;    // Version code so upgrades don't break.
  uint64_t id;         // Arbitrary ID number given by creator.
  uint32_t name;       // Reference to stored name string.

  // Above is read-only after first construction. Below may be changed and
  // so must be marked "volatile" to provide correct inter-process behavior.

  // Bitfield of information flags. Access to this should be done through
  // the CheckFlag() and SetFlag() methods defined above.
  volatile std::atomic<uint32_t> flags;

  // Offset/reference to first free space in segment.
  volatile std::atomic<uint32_t> freeptr;

  // The "iterable" queue is an M&S Queue as described here, append-only:
  // https://www.research.ibm.com/people/m/michael/podc-1996.pdf
  volatile std::atomic<uint32_t> tailptr;  // Last block of iteration queue.
  volatile BlockHeader queue;   // Empty block for linked-list head/tail.
};

// The "queue" block header is used to detect "last node" so that zero/null
// can be used to indicate that it hasn't been added at all. It is part of
// the SharedMetadata structure which itself is always located at offset zero.
const PersistentMemoryAllocator::Reference
    PersistentMemoryAllocator::kReferenceQueue =
        offsetof(SharedMetadata, queue);
const PersistentMemoryAllocator::Reference
    PersistentMemoryAllocator::kReferenceNull = 0;


// static
bool PersistentMemoryAllocator::IsMemoryAcceptable(const void* base,
                                                   size_t size,
                                                   size_t page_size,
                                                   bool readonly) {
  return ((base && reinterpret_cast<uintptr_t>(base) % kAllocAlignment == 0) &&
          (size >= sizeof(SharedMetadata) && size <= kSegmentMaxSize) &&
          (size >= kSegmentMinSize || readonly) &&
          (size % kAllocAlignment == 0 || readonly) &&
          (page_size == 0 || size % page_size == 0 || readonly));
}

PersistentMemoryAllocator::PersistentMemoryAllocator(
    void* base,
    size_t size,
    size_t page_size,
    uint64_t id,
    base::StringPiece name,
    bool readonly)
    : mem_base_(static_cast<char*>(base)),
      mem_size_(static_cast<uint32_t>(size)),
      mem_page_(static_cast<uint32_t>((page_size ? page_size : size))),
      readonly_(readonly),
      corrupt_(0),
      allocs_histogram_(nullptr),
      used_histogram_(nullptr) {
  static_assert(sizeof(BlockHeader) % kAllocAlignment == 0,
                "BlockHeader is not a multiple of kAllocAlignment");
  static_assert(sizeof(SharedMetadata) % kAllocAlignment == 0,
                "SharedMetadata is not a multiple of kAllocAlignment");
  static_assert(kReferenceQueue % kAllocAlignment == 0,
                "\"queue\" is not aligned properly; must be at end of struct");

  // Ensure that memory segment is of acceptable size.
  CHECK(IsMemoryAcceptable(base, size, page_size, readonly));

  // These atomics operate inter-process and so must be lock-free. The local
  // casts are to make sure it can be evaluated at compile time to a constant.
  CHECK(((SharedMetadata*)0)->freeptr.is_lock_free());
  CHECK(((SharedMetadata*)0)->flags.is_lock_free());
  CHECK(((BlockHeader*)0)->next.is_lock_free());
  CHECK(corrupt_.is_lock_free());

  if (shared_meta()->cookie != kGlobalCookie) {
    if (readonly) {
      SetCorrupt();
      return;
    }

    // This block is only executed when a completely new memory segment is
    // being initialized. It's unshared and single-threaded...
    volatile BlockHeader* const first_block =
        reinterpret_cast<volatile BlockHeader*>(mem_base_ +
                                                sizeof(SharedMetadata));
    if (shared_meta()->cookie != 0 ||
        shared_meta()->size != 0 ||
        shared_meta()->version != 0 ||
        shared_meta()->freeptr.load() != 0 ||
        shared_meta()->flags.load() != 0 ||
        shared_meta()->id != 0 ||
        shared_meta()->name != 0 ||
        shared_meta()->tailptr != 0 ||
        shared_meta()->queue.cookie != 0 ||
        shared_meta()->queue.next.load() != 0 ||
        first_block->size != 0 ||
        first_block->cookie != 0 ||
        first_block->type_id != 0 ||
        first_block->next != 0) {
      // ...or something malicious has been playing with the metadata.
      NOTREACHED();
      SetCorrupt();
    }

    // This is still safe to do even if corruption has been detected.
    shared_meta()->cookie = kGlobalCookie;
    shared_meta()->size = mem_size_;
    shared_meta()->page_size = mem_page_;
    shared_meta()->version = kGlobalVersion;
    shared_meta()->id = id;
    shared_meta()->freeptr.store(sizeof(SharedMetadata));

    // Set up the queue of iterable allocations.
    shared_meta()->queue.size = sizeof(BlockHeader);
    shared_meta()->queue.cookie = kBlockCookieQueue;
    shared_meta()->queue.next.store(kReferenceQueue);
    shared_meta()->tailptr.store(kReferenceQueue);

    // Allocate space for the name so other processes can learn it.
    if (!name.empty()) {
      const size_t name_length = name.length() + 1;
      shared_meta()->name = Allocate(name_length, 0);
      char* name_cstr = GetAsObject<char>(shared_meta()->name, 0);
      if (name_cstr)
        memcpy(name_cstr, name.data(), name.length());
    }
  } else {
    if (shared_meta()->size == 0 ||
        shared_meta()->version == 0 ||
        shared_meta()->freeptr.load() == 0 ||
        shared_meta()->tailptr == 0 ||
        shared_meta()->queue.cookie == 0 ||
        shared_meta()->queue.next.load() == 0) {
      SetCorrupt();
    }
    if (!readonly) {
      // The allocator is attaching to a previously initialized segment of
      // memory. Make sure the embedded data matches what has been passed.
      if (shared_meta()->size != mem_size_ ||
          shared_meta()->page_size != mem_page_) {
        NOTREACHED();
        SetCorrupt();
      }
    }
  }
}

PersistentMemoryAllocator::~PersistentMemoryAllocator() {
  // It's strictly forbidden to do any memory access here in case there is
  // some issue with the underlying memory segment. The "Local" allocator
  // makes use of this to allow deletion of the segment on the heap from
  // within its destructor.
}

uint64_t PersistentMemoryAllocator::Id() const {
  return shared_meta()->id;
}

const char* PersistentMemoryAllocator::Name() const {
  Reference name_ref = shared_meta()->name;
  const char* name_cstr = GetAsObject<char>(name_ref, 0);
  if (!name_cstr)
    return "";

  size_t name_length = GetAllocSize(name_ref);
  if (name_cstr[name_length - 1] != '\0') {
    NOTREACHED();
    SetCorrupt();
    return "";
  }

  return name_cstr;
}

void PersistentMemoryAllocator::CreateTrackingHistograms(
    base::StringPiece name) {
  if (name.empty() || readonly_)
    return;

  std::string name_string = name.as_string();
  DCHECK(!used_histogram_);
  used_histogram_ = LinearHistogram::FactoryGet(
      "UMA.PersistentAllocator." + name_string + ".UsedPct", 1, 101, 21,
      HistogramBase::kUmaTargetedHistogramFlag);

  DCHECK(!allocs_histogram_);
  allocs_histogram_ = Histogram::FactoryGet(
      "UMA.PersistentAllocator." + name_string + ".Allocs", 1, 10000, 50,
      HistogramBase::kUmaTargetedHistogramFlag);
}

size_t PersistentMemoryAllocator::used() const {
  return std::min(shared_meta()->freeptr.load(), mem_size_);
}

size_t PersistentMemoryAllocator::GetAllocSize(Reference ref) const {
  const volatile BlockHeader* const block = GetBlock(ref, 0, 0, false, false);
  if (!block)
    return 0;
  uint32_t size = block->size;
  // Header was verified by GetBlock() but a malicious actor could change
  // the value between there and here. Check it again.
  if (size <= sizeof(BlockHeader) || ref + size > mem_size_) {
    SetCorrupt();
    return 0;
  }
  return size - sizeof(BlockHeader);
}

uint32_t PersistentMemoryAllocator::GetType(Reference ref) const {
  const volatile BlockHeader* const block = GetBlock(ref, 0, 0, false, false);
  if (!block)
    return 0;
  return block->type_id;
}

void PersistentMemoryAllocator::SetType(Reference ref, uint32_t type_id) {
  DCHECK(!readonly_);
  volatile BlockHeader* const block = GetBlock(ref, 0, 0, false, false);
  if (!block)
    return;
  block->type_id = type_id;
}

PersistentMemoryAllocator::Reference PersistentMemoryAllocator::Allocate(
    size_t req_size,
    uint32_t type_id) {
  Reference ref = AllocateImpl(req_size, type_id);
  if (ref) {
    // Success: Record this allocation in usage stats (if active).
    if (allocs_histogram_)
      allocs_histogram_->Add(static_cast<HistogramBase::Sample>(req_size));
  } else {
    // Failure: Record an allocation of zero for tracking.
    if (allocs_histogram_)
      allocs_histogram_->Add(0);
  }
  return ref;
}

PersistentMemoryAllocator::Reference PersistentMemoryAllocator::AllocateImpl(
    size_t req_size,
    uint32_t type_id) {
  DCHECK(!readonly_);

  // Validate req_size to ensure it won't overflow when used as 32-bit value.
  if (req_size > kSegmentMaxSize - sizeof(BlockHeader)) {
    NOTREACHED();
    return kReferenceNull;
  }

  // Round up the requested size, plus header, to the next allocation alignment.
  uint32_t size = static_cast<uint32_t>(req_size + sizeof(BlockHeader));
  size = (size + (kAllocAlignment - 1)) & ~(kAllocAlignment - 1);
  if (size <= sizeof(BlockHeader) || size > mem_page_) {
    NOTREACHED();
    return kReferenceNull;
  }

  // Get the current start of unallocated memory. Other threads may
  // update this at any time and cause us to retry these operations.
  // This value should be treated as "const" to avoid confusion through
  // the code below but recognize that any failed compare-exchange operation
  // involving it will cause it to be loaded with a more recent value. The
  // code should either exit or restart the loop in that case.
  /* const */ uint32_t freeptr = shared_meta()->freeptr.load();

  // Allocation is lockless so we do all our caculation and then, if saving
  // indicates a change has occurred since we started, scrap everything and
  // start over.
  for (;;) {
    if (IsCorrupt())
      return kReferenceNull;

    if (freeptr + size > mem_size_) {
      SetFlag(&shared_meta()->flags, kFlagFull);
      return kReferenceNull;
    }

    // Get pointer to the "free" block. If something has been allocated since
    // the load of freeptr above, it is still safe as nothing will be written
    // to that location until after the compare-exchange below.
    volatile BlockHeader* const block = GetBlock(freeptr, 0, 0, false, true);
    if (!block) {
      SetCorrupt();
      return kReferenceNull;
    }

    // An allocation cannot cross page boundaries. If it would, create a
    // "wasted" block and begin again at the top of the next page. This
    // area could just be left empty but we fill in the block header just
    // for completeness sake.
    const uint32_t page_free = mem_page_ - freeptr % mem_page_;
    if (size > page_free) {
      if (page_free <= sizeof(BlockHeader)) {
        SetCorrupt();
        return kReferenceNull;
      }
      const uint32_t new_freeptr = freeptr + page_free;
      if (shared_meta()->freeptr.compare_exchange_strong(freeptr,
                                                         new_freeptr)) {
        block->size = page_free;
        block->cookie = kBlockCookieWasted;
      }
      continue;
    }

    // Don't leave a slice at the end of a page too small for anything. This
    // can result in an allocation up to two alignment-sizes greater than the
    // minimum required by requested-size + header + alignment.
    if (page_free - size < sizeof(BlockHeader) + kAllocAlignment)
      size = page_free;

    const uint32_t new_freeptr = freeptr + size;
    if (new_freeptr > mem_size_) {
      SetCorrupt();
      return kReferenceNull;
    }

    // Save our work. Try again if another thread has completed an allocation
    // while we were processing. A "weak" exchange would be permissable here
    // because the code will just loop and try again but the above processing
    // is significant so make the extra effort of a "strong" exchange.
    if (!shared_meta()->freeptr.compare_exchange_strong(freeptr, new_freeptr))
      continue;

    // Given that all memory was zeroed before ever being given to an instance
    // of this class and given that we only allocate in a monotomic fashion
    // going forward, it must be that the newly allocated block is completely
    // full of zeros. If we find anything in the block header that is NOT a
    // zero then something must have previously run amuck through memory,
    // writing beyond the allocated space and into unallocated space.
    if (block->size != 0 ||
        block->cookie != kBlockCookieFree ||
        block->type_id != 0 ||
        block->next.load() != 0) {
      SetCorrupt();
      return kReferenceNull;
    }

    block->size = size;
    block->cookie = kBlockCookieAllocated;
    block->type_id = type_id;
    return freeptr;
  }
}

void PersistentMemoryAllocator::GetMemoryInfo(MemoryInfo* meminfo) const {
  uint32_t remaining = std::max(mem_size_ - shared_meta()->freeptr.load(),
                                (uint32_t)sizeof(BlockHeader));
  meminfo->total = mem_size_;
  meminfo->free = IsCorrupt() ? 0 : remaining - sizeof(BlockHeader);
}

void PersistentMemoryAllocator::MakeIterable(Reference ref) {
  DCHECK(!readonly_);
  if (IsCorrupt())
    return;
  volatile BlockHeader* block = GetBlock(ref, 0, 0, false, false);
  if (!block)  // invalid reference
    return;
  if (block->next.load(std::memory_order_acquire) != 0)  // Already iterable.
    return;
  block->next.store(kReferenceQueue, std::memory_order_release);  // New tail.

  // Try to add this block to the tail of the queue. May take multiple tries.
  // If so, tail will be automatically updated with a more recent value during
  // compare-exchange operations.
  uint32_t tail = shared_meta()->tailptr.load(std::memory_order_acquire);
  for (;;) {
    // Acquire the current tail-pointer released by previous call to this
    // method and validate it.
    block = GetBlock(tail, 0, 0, true, false);
    if (!block) {
      SetCorrupt();
      return;
    }

    // Try to insert the block at the tail of the queue. The tail node always
    // has an existing value of kReferenceQueue; if that is somehow not the
    // existing value then another thread has acted in the meantime. A "strong"
    // exchange is necessary so the "else" block does not get executed when
    // that is not actually the case (which can happen with a "weak" exchange).
    uint32_t next = kReferenceQueue;  // Will get replaced with existing value.
    if (block->next.compare_exchange_strong(next, ref,
                                            std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
      // Update the tail pointer to the new offset. If the "else" clause did
      // not exist, then this could be a simple Release_Store to set the new
      // value but because it does, it's possible that other threads could add
      // one or more nodes at the tail before reaching this point. We don't
      // have to check the return value because it either operates correctly
      // or the exact same operation has already been done (by the "else"
      // clause) on some other thread.
      shared_meta()->tailptr.compare_exchange_strong(tail, ref,
                                                     std::memory_order_release,
                                                     std::memory_order_relaxed);
      return;
    } else {
      // In the unlikely case that a thread crashed or was killed between the
      // update of "next" and the update of "tailptr", it is necessary to
      // perform the operation that would have been done. There's no explicit
      // check for crash/kill which means that this operation may also happen
      // even when the other thread is in perfect working order which is what
      // necessitates the CompareAndSwap above.
      shared_meta()->tailptr.compare_exchange_strong(tail, next,
                                                     std::memory_order_acq_rel,
                                                     std::memory_order_acquire);
    }
  }
}

void PersistentMemoryAllocator::CreateIterator(Iterator* state,
                                               Reference starting_after) const {
  if (starting_after) {
    // Ensure that the starting point is a valid, iterable block.
    const volatile BlockHeader* block =
        GetBlock(starting_after, 0, 0, false, false);
    if (!block || !block->next.load()) {
      NOTREACHED();
      starting_after = kReferenceQueue;
    }
  } else {
    // A zero beginning is really the Queue reference.
    starting_after = kReferenceQueue;
  }

  state->last = starting_after;
  state->niter = 0;
}

PersistentMemoryAllocator::Reference PersistentMemoryAllocator::GetNextIterable(
    Iterator* state,
    uint32_t* type_id) const {
  const volatile BlockHeader* block = GetBlock(state->last, 0, 0, true, false);
  if (!block)  // invalid iterator state
    return kReferenceNull;

  // The compiler and CPU can freely reorder all memory accesses on which
  // there are no dependencies. It could, for example, move the load of
  // "freeptr" above this point because there are no explicit dependencies
  // between it and "next". If it did, however, then another block could
  // be queued after that but before the following load meaning there is
  // one more queued block than the future "detect loop by having more
  // blocks that could fit before freeptr" will allow.
  //
  // By "acquiring" the "next" value here, it's synchronized to the enqueue
  // of the node which in turn is synchronized to the allocation (which sets
  // freeptr). Thus, the scenario above cannot happen.
  uint32_t next = block->next.load(std::memory_order_acquire);
  block = GetBlock(next, 0, 0, false, false);
  if (!block)  // no next allocation in queue
    return kReferenceNull;

  // Memory corruption could cause a loop in the list. We need to detect
  // that so as to not cause an infinite loop in the caller. We do this
  // simply by making sure we don't iterate more than the absolute maximum
  // number of allocations that could have been made. Callers are likely
  // to loop multiple times before it is detected but at least it stops.
  uint32_t freeptr = std::min(
      shared_meta()->freeptr.load(std::memory_order_acquire),
      mem_size_);
  if (state->niter > freeptr / (sizeof(BlockHeader) + kAllocAlignment)) {
    SetCorrupt();
    return kReferenceNull;
  }

  state->last = next;
  state->niter++;
  *type_id = block->type_id;

  return next;
}

// The "corrupted" state is held both locally and globally (shared). The
// shared flag can't be trusted since a malicious actor could overwrite it.
// Because corruption can be detected during read-only operations such as
// iteration, this method may be called by other "const" methods. In this
// case, it's safe to discard the constness and modify the local flag and
// maybe even the shared flag if the underlying data isn't actually read-only.
void PersistentMemoryAllocator::SetCorrupt() const {
  LOG(ERROR) << "Corruption detected in shared-memory segment.";
  const_cast<std::atomic<bool>*>(&corrupt_)->store(true);
  if (!readonly_) {
    SetFlag(const_cast<volatile std::atomic<uint32_t>*>(&shared_meta()->flags),
            kFlagCorrupt);
  }
}

bool PersistentMemoryAllocator::IsCorrupt() const {
  if (corrupt_.load() || CheckFlag(&shared_meta()->flags, kFlagCorrupt)) {
    SetCorrupt();  // Make sure all indicators are set.
    return true;
  }
  return false;
}

bool PersistentMemoryAllocator::IsFull() const {
  return CheckFlag(&shared_meta()->flags, kFlagFull);
}

// Dereference a block |ref| and ensure that it's valid for the desired
// |type_id| and |size|. |special| indicates that we may try to access block
// headers not available to callers but still accessed by this module. By
// having internal dereferences go through this same function, the allocator
// is hardened against corruption.
const volatile PersistentMemoryAllocator::BlockHeader*
PersistentMemoryAllocator::GetBlock(Reference ref, uint32_t type_id,
                                    uint32_t size, bool queue_ok,
                                    bool free_ok) const {
  // Validation of parameters.
  if (ref % kAllocAlignment != 0)
    return nullptr;
  if (ref < (queue_ok ? kReferenceQueue : sizeof(SharedMetadata)))
    return nullptr;
  size += sizeof(BlockHeader);
  if (ref + size > mem_size_)
    return nullptr;

  // Validation of referenced block-header.
  if (!free_ok) {
    uint32_t freeptr = shared_meta()->freeptr.load();
    if (ref + size > freeptr)
      return nullptr;
    const volatile BlockHeader* const block =
        reinterpret_cast<volatile BlockHeader*>(mem_base_ + ref);
    if (block->size < size)
      return nullptr;
    if (ref != kReferenceQueue && block->cookie != kBlockCookieAllocated)
      return nullptr;
    if (type_id != 0 && block->type_id != type_id)
      return nullptr;
  }

  // Return pointer to block data.
  return reinterpret_cast<const volatile BlockHeader*>(mem_base_ + ref);
}

const volatile void* PersistentMemoryAllocator::GetBlockData(
    Reference ref,
    uint32_t type_id,
    uint32_t size) const {
  DCHECK(size > 0);
  const volatile BlockHeader* block =
      GetBlock(ref, type_id, size, false, false);
  if (!block)
    return nullptr;
  return reinterpret_cast<const volatile char*>(block) + sizeof(BlockHeader);
}

void PersistentMemoryAllocator::UpdateTrackingHistograms() {
  DCHECK(!readonly_);
  if (used_histogram_) {
    MemoryInfo meminfo;
    GetMemoryInfo(&meminfo);
    HistogramBase::Sample used_percent = static_cast<HistogramBase::Sample>(
        ((meminfo.total - meminfo.free) * 100ULL / meminfo.total));
    used_histogram_->Add(used_percent);
  }
}


//----- LocalPersistentMemoryAllocator -----------------------------------------

LocalPersistentMemoryAllocator::LocalPersistentMemoryAllocator(
    size_t size,
    uint64_t id,
    base::StringPiece name)
    : PersistentMemoryAllocator(memset(new char[size], 0, size),
                                size, 0, id, name, false) {}

LocalPersistentMemoryAllocator::~LocalPersistentMemoryAllocator() {
  delete [] mem_base_;
}


//----- SharedPersistentMemoryAllocator ----------------------------------------
#if 0

SharedPersistentMemoryAllocator::SharedPersistentMemoryAllocator(
    std::unique_ptr<SharedMemory> memory,
    uint64_t id,
    base::StringPiece name,
    bool read_only)
    : PersistentMemoryAllocator(static_cast<uint8_t*>(memory->memory()),
                                memory->mapped_size(),
                                0,
                                id,
                                name,
                                read_only),
      shared_memory_(std::move(memory)) {}

SharedPersistentMemoryAllocator::~SharedPersistentMemoryAllocator() {}

// static
bool SharedPersistentMemoryAllocator::IsSharedMemoryAcceptable(
    const SharedMemory& memory) {
  return IsMemoryAcceptable(memory.memory(), memory.mapped_size(), 0, true);
}


//----- FilePersistentMemoryAllocator ------------------------------------------

FilePersistentMemoryAllocator::FilePersistentMemoryAllocator(
    std::unique_ptr<MemoryMappedFile> file,
    uint64_t id,
    base::StringPiece name)
    : PersistentMemoryAllocator(const_cast<uint8_t*>(file->data()),
                                file->length(),
                                0,
                                id,
                                name,
                                true),
      mapped_file_(std::move(file)) {}

FilePersistentMemoryAllocator::~FilePersistentMemoryAllocator() {}

// static
bool FilePersistentMemoryAllocator::IsFileAcceptable(
    const MemoryMappedFile& file) {
  return IsMemoryAcceptable(file.data(), file.length(), 0, true);
}
#endif

}  // namespace base
