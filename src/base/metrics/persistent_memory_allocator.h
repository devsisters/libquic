// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_PERSISTENT_MEMORY_ALLOCATOR_H_
#define BASE_METRICS_PERSISTENT_MEMORY_ALLOCATOR_H_

#include <stdint.h>
#include <atomic>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/memory/scoped_ptr.h"
#include "base/strings/string_piece.h"

namespace base {

class HistogramBase;
class MemoryMappedFile;
class SharedMemory;

// Simple allocator for pieces of a memory block that may be persistent
// to some storage or shared across multiple processes. This class resides
// under base/metrics because it was written for that purpose. It is,
// however, fully general-purpose and can be freely moved to base/memory
// if other uses are found.
//
// This class provides for thread-secure (i.e. safe against other threads
// or processes that may be compromised and thus have malicious intent)
// allocation of memory within a designated block and also a mechanism by
// which other threads can learn of these allocations.
//
// There is (currently) no way to release an allocated block of data because
// doing so would risk invalidating pointers held by other processes and
// greatly complicate the allocation algorithm.
//
// Construction of this object can accept new, clean (i.e. zeroed) memory
// or previously initialized memory. In the first case, construction must
// be allowed to complete before letting other allocators attach to the same
// segment. In other words, don't share the segment until at least one
// allocator has been attached to it.
//
// Note that memory not in active use is not accessed so it is possible to
// use virtual memory, including memory-mapped files, as backing storage with
// the OS "pinning" new (zeroed) physical RAM pages only as they are needed.
class BASE_EXPORT PersistentMemoryAllocator {
 public:
  typedef uint32_t Reference;

  // Internal state information when iterating over memory allocations.
  class Iterator {
   public:
    Iterator() : last(0) {}

    bool operator==(const Iterator& rhs) const { return last == rhs.last; }
    bool operator!=(const Iterator& rhs) const { return last != rhs.last; }

    void clear() { last = 0; }
    bool is_clear() const { return last == 0; }

   private:
    friend class PersistentMemoryAllocator;

    Reference last;
    uint32_t niter;
  };

  // Returned information about the internal state of the heap.
  struct MemoryInfo {
    size_t total;
    size_t free;
  };

  enum : uint32_t {
    kTypeIdAny = 0  // Match any type-id inside GetAsObject().
  };

  // The allocator operates on any arbitrary block of memory. Creation and
  // persisting or sharing of that block with another process is the
  // responsibility of the caller. The allocator needs to know only the
  // block's |base| address, the total |size| of the block, and any internal
  // |page| size (zero if not paged) across which allocations should not span.
  // The |id| is an arbitrary value the caller can use to identify a
  // particular memory segment. It will only be loaded during the initial
  // creation of the segment and can be checked by the caller for consistency.
  // The |name|, if provided, is used to distinguish histograms for this
  // allocator. Only the primary owner of the segment should define this value;
  // other processes can learn it from the shared state. If the underlying
  // memory is |readonly| then no changes will be made to it. The resulting
  // object should be stored as a "const" pointer.
  //
  // PersistentMemoryAllocator does NOT take ownership of the memory block.
  // The caller must manage it and ensure it stays available throughout the
  // lifetime of this object.
  //
  // Memory segments for sharing must have had an allocator attached to them
  // before actually being shared. If the memory segment was just created, it
  // should be zeroed before being passed here. If it was an existing segment,
  // the values here will be compared to copies stored in the shared segment
  // as a guard against corruption.
  //
  // Make sure that the memory segment is acceptable (see IsMemoryAcceptable()
  // method below) before construction if the definition of the segment can
  // vary in any way at run-time. Invalid memory segments will cause a crash.
  PersistentMemoryAllocator(void* base, size_t size, size_t page_size,
                            uint64_t id, base::StringPiece name,
                            bool readonly);
  virtual ~PersistentMemoryAllocator();

  // Check if memory segment is acceptable for creation of an Allocator. This
  // doesn't do any analysis of the data and so doesn't guarantee that the
  // contents are valid, just that the paramaters won't cause the program to
  // abort. The IsCorrupt() method will report detection of data problems
  // found during construction and general operation.
  static bool IsMemoryAcceptable(const void* data, size_t size,
                                 size_t page_size, bool readonly);

  // Get the internal identifier for this persistent memory segment.
  uint64_t Id() const;

  // Get the internal name of this allocator (possibly an empty string).
  const char* Name() const;

  // Is this segment open only for read?
  bool IsReadonly() { return readonly_; }

  // Create internal histograms for tracking memory use and allocation sizes
  // for allocator of |name| (which can simply be the result of Name()). This
  // is done seperately from construction for situations such as when the
  // histograms will be backed by memory provided by this very allocator.
  //
  // IMPORTANT: Callers must update tools/metrics/histograms/histograms.xml
  // with the following histograms:
  //    UMA.PersistentAllocator.name.Allocs
  //    UMA.PersistentAllocator.name.UsedPct
  void CreateTrackingHistograms(base::StringPiece name);

  // Direct access to underlying memory segment. If the segment is shared
  // across threads or processes, reading data through these values does
  // not guarantee consistency. Use with care. Do not write.
  const void* data() const { return const_cast<const char*>(mem_base_); }
  size_t length() const { return mem_size_; }
  size_t used() const;

  // Get an object referenced by a |ref|. For safety reasons, the |type_id|
  // code and size-of(|T|) are compared to ensure the reference is valid
  // and cannot return an object outside of the memory segment. A |type_id| of
  // kTypeIdAny (zero) will match any though the size is still checked. NULL is
  // returned if any problem is detected, such as corrupted storage or incorrect
  // parameters. Callers MUST check that the returned value is not-null EVERY
  // TIME before accessing it or risk crashing! Once dereferenced, the pointer
  // is safe to reuse forever.
  //
  // NOTE: Though this method will guarantee that an object of the specified
  // type can be accessed without going outside the bounds of the memory
  // segment, it makes no guarantees of the validity of the data within the
  // object itself. If it is expected that the contents of the segment could
  // be compromised with malicious intent, the object must be hardened as well.
  //
  // Though the persistent data may be "volatile" if it is shared with
  // other processes, such is not necessarily the case. The internal
  // "volatile" designation is discarded so as to not propagate the viral
  // nature of that keyword to the caller. It can add it back, if necessary,
  // based on knowledge of how the allocator is being used.
  template <typename T>
  T* GetAsObject(Reference ref, uint32_t type_id) {
    static_assert(!std::is_polymorphic<T>::value, "no polymorphic objects");
    return const_cast<T*>(
        reinterpret_cast<volatile T*>(GetBlockData(ref, type_id, sizeof(T))));
  }
  template <typename T>
  const T* GetAsObject(Reference ref, uint32_t type_id) const {
    static_assert(!std::is_polymorphic<T>::value, "no polymorphic objects");
    return const_cast<const T*>(
        reinterpret_cast<const volatile T*>(GetBlockData(
            ref, type_id, sizeof(T))));
  }

  // Get the number of bytes allocated to a block. This is useful when storing
  // arrays in order to validate the ending boundary. The returned value will
  // include any padding added to achieve the required alignment and so could
  // be larger than given in the original Allocate() request.
  size_t GetAllocSize(Reference ref) const;

  // Access the internal "type" of an object. This generally isn't necessary
  // but can be used to "clear" the type and so effectively mark it as deleted
  // even though the memory stays valid and allocated.
  uint32_t GetType(Reference ref) const;
  void SetType(Reference ref, uint32_t type_id);

  // Reserve space in the memory segment of the desired |size| and |type_id|.
  // A return value of zero indicates the allocation failed, otherwise the
  // returned reference can be used by any process to get a real pointer via
  // the GetAsObject() call.
  Reference Allocate(size_t size, uint32_t type_id);

  // Allocated objects can be added to an internal list that can then be
  // iterated over by other processes. If an allocated object can be found
  // another way, such as by having its reference within a different object
  // that will be made iterable, then this call is not necessary. This always
  // succeeds unless corruption is detected; check IsCorrupted() to find out.
  // Once an object is made iterable, its position in iteration can never
  // change; new iterable objects will always be added after it in the series.
  void MakeIterable(Reference ref);

  // Get the information about the amount of free space in the allocator. The
  // amount of free space should be treated as approximate due to extras from
  // alignment and metadata. Concurrent allocations from other threads will
  // also make the true amount less than what is reported.
  void GetMemoryInfo(MemoryInfo* meminfo) const;

  // Iterating uses a |state| structure (initialized by CreateIterator) and
  // returns both the reference to the object as well as the |type_id| of
  // that object. A zero return value indicates there are currently no more
  // objects to be found but future attempts can be made without having to
  // reset the iterator to "first". Creating an iterator |starting_after|
  // a known iterable object allows "resume" from that point with the next
  // call to GetNextIterable returning the object after it.
  void CreateIterator(Iterator* state) const { CreateIterator(state, 0); };
  void CreateIterator(Iterator* state, Reference starting_after) const;
  Reference GetNextIterable(Iterator* state, uint32_t* type_id) const;

  // If there is some indication that the memory has become corrupted,
  // calling this will attempt to prevent further damage by indicating to
  // all processes that something is not as expected.
  void SetCorrupt() const;

  // This can be called to determine if corruption has been detected in the
  // segment, possibly my a malicious actor. Once detected, future allocations
  // will fail and iteration may not locate all objects.
  bool IsCorrupt() const;

  // Flag set if an allocation has failed because the memory segment was full.
  bool IsFull() const;

  // Update those "tracking" histograms which do not get updates during regular
  // operation, such as how much memory is currently used. This should be
  // called before such information is to be displayed or uploaded.
  void UpdateTrackingHistograms();

 protected:
  volatile char* const mem_base_;  // Memory base. (char so sizeof guaranteed 1)
  const uint32_t mem_size_;        // Size of entire memory segment.
  const uint32_t mem_page_;        // Page size allocations shouldn't cross.

 private:
  struct SharedMetadata;
  struct BlockHeader;
  static const uint32_t kAllocAlignment;
  static const Reference kReferenceQueue;
  static const Reference kReferenceNull;

  // The shared metadata is always located at the top of the memory segment.
  // These convenience functions eliminate constant casting of the base
  // pointer within the code.
  const SharedMetadata* shared_meta() const {
    return reinterpret_cast<const SharedMetadata*>(
        const_cast<const char*>(mem_base_));
  }
  SharedMetadata* shared_meta() {
    return reinterpret_cast<SharedMetadata*>(const_cast<char*>(mem_base_));
  }

  // Actual method for doing the allocation.
  Reference AllocateImpl(size_t size, uint32_t type_id);

  // Get the block header associated with a specific reference.
  const volatile BlockHeader* GetBlock(Reference ref, uint32_t type_id,
                                       uint32_t size, bool queue_ok,
                                       bool free_ok) const;
  volatile BlockHeader* GetBlock(Reference ref, uint32_t type_id, uint32_t size,
                                 bool queue_ok, bool free_ok) {
      return const_cast<volatile BlockHeader*>(
          const_cast<const PersistentMemoryAllocator*>(this)->GetBlock(
              ref, type_id, size, queue_ok, free_ok));
  }

  // Get the actual data within a block associated with a specific reference.
  const volatile void* GetBlockData(Reference ref, uint32_t type_id,
                                    uint32_t size) const;
  volatile void* GetBlockData(Reference ref, uint32_t type_id,
                              uint32_t size) {
      return const_cast<volatile void*>(
          const_cast<const PersistentMemoryAllocator*>(this)->GetBlockData(
              ref, type_id, size));
  }

  const bool readonly_;              // Indicates access to read-only memory.
  std::atomic<bool> corrupt_;        // Local version of "corrupted" flag.

  HistogramBase* allocs_histogram_;  // Histogram recording allocs.
  HistogramBase* used_histogram_;    // Histogram recording used space.

  friend class PersistentMemoryAllocatorTest;
  FRIEND_TEST_ALL_PREFIXES(PersistentMemoryAllocatorTest, AllocateAndIterate);
  DISALLOW_COPY_AND_ASSIGN(PersistentMemoryAllocator);
};


// This allocator uses a local memory block it allocates from the general
// heap. It is generally used when some kind of "death rattle" handler will
// save the contents to persistent storage during process shutdown. It is
// also useful for testing.
class BASE_EXPORT LocalPersistentMemoryAllocator
    : public PersistentMemoryAllocator {
 public:
  LocalPersistentMemoryAllocator(size_t size, uint64_t id,
                                 base::StringPiece name);
  ~LocalPersistentMemoryAllocator() override;

 private:
  DISALLOW_COPY_AND_ASSIGN(LocalPersistentMemoryAllocator);
};


// This allocator takes a shared-memory object and performs allocation from
// it. The memory must be previously mapped via Map() or MapAt(). The allocator
// takes ownership of the memory object.
class BASE_EXPORT SharedPersistentMemoryAllocator
    : public PersistentMemoryAllocator {
 public:
  SharedPersistentMemoryAllocator(scoped_ptr<SharedMemory> memory, uint64_t id,
                                  base::StringPiece name, bool read_only);
  ~SharedPersistentMemoryAllocator() override;

  SharedMemory* shared_memory() { return shared_memory_.get(); }

  // Ensure that the memory isn't so invalid that it won't crash when passing it
  // to the allocator. This doesn't guarantee the data is valid, just that it
  // won't cause the program to abort. The existing IsCorrupt() call will handle
  // the rest.
  static bool IsSharedMemoryAcceptable(const SharedMemory& memory);

 private:
  scoped_ptr<SharedMemory> shared_memory_;

  DISALLOW_COPY_AND_ASSIGN(SharedPersistentMemoryAllocator);
};


// This allocator takes a memory-mapped file object and performs allocation
// from it. The allocator takes ownership of the file object. Only read access
// is provided due to limitions of the MemoryMappedFile class.
class BASE_EXPORT FilePersistentMemoryAllocator
    : public PersistentMemoryAllocator {
 public:
  FilePersistentMemoryAllocator(scoped_ptr<MemoryMappedFile> file, uint64_t id,
                                base::StringPiece name);
  ~FilePersistentMemoryAllocator() override;

  // Ensure that the file isn't so invalid that it won't crash when passing it
  // to the allocator. This doesn't guarantee the file is valid, just that it
  // won't cause the program to abort. The existing IsCorrupt() call will handle
  // the rest.
  static bool IsFileAcceptable(const MemoryMappedFile& file);

 private:
  scoped_ptr<MemoryMappedFile> mapped_file_;

  DISALLOW_COPY_AND_ASSIGN(FilePersistentMemoryAllocator);
};

}  // namespace base

#endif  // BASE_METRICS_PERSISTENT_MEMORY_ALLOCATOR_H_
