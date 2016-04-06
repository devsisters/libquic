// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_HISTOGRAM_PERSISTENCE_H_
#define BASE_METRICS_HISTOGRAM_PERSISTENCE_H_

#include <memory>

#include "base/atomicops.h"
#include "base/base_export.h"
#include "base/feature_list.h"
#if 0
#include "base/memory/shared_memory.h"
#endif
#include "base/metrics/histogram_base.h"
#include "base/metrics/persistent_memory_allocator.h"
#include "base/strings/string_piece.h"

namespace base {

// Feature definition for enabling histogram persistence.
BASE_EXPORT extern const Feature kPersistentHistogramsFeature;

// This class manages histograms created within a PersistentMemoryAllocator.
class BASE_EXPORT PersistentHistogramAllocator {
 public:
  // This iterator is used for fetching persistent histograms from an allocator.
  class Iterator {
   public:
    bool is_clear() { return memory_iter.is_clear(); }

   private:
    friend class PersistentHistogramAllocator;

    // The iterator used for stepping through persistent memory iterables.
    PersistentMemoryAllocator::Iterator memory_iter;
  };

  using Reference = PersistentMemoryAllocator::Reference;

  // A PersistentHistogramAllocator is constructed from a PersistentMemory-
  // Allocator object of which it takes ownership.
  PersistentHistogramAllocator(
      std::unique_ptr<PersistentMemoryAllocator> memory);
  ~PersistentHistogramAllocator();

  // Direct access to underlying memory allocator. If the segment is shared
  // across threads or processes, reading data through these values does
  // not guarantee consistency. Use with care. Do not write.
  PersistentMemoryAllocator* memory_allocator() {
    return memory_allocator_.get();
  }

  // Implement the "metadata" API of a PersistentMemoryAllocator, forwarding
  // those requests to the real one.
  uint64_t Id() const { return memory_allocator_->Id(); }
  const char* Name() const { return memory_allocator_->Name(); }
  const void* data() const { return memory_allocator_->data(); }
  size_t length() const { return memory_allocator_->length(); }
  size_t used() const { return memory_allocator_->used(); }

  // Recreate a Histogram from data held in persistent memory. Though this
  // object will be local to the current process, the sample data will be
  // shared with all other threads referencing it. This method takes a |ref|
  // to where the top-level histogram data may be found in this allocator.
  // This method will return null if any problem is detected with the data.
  std::unique_ptr<HistogramBase> GetHistogram(Reference ref);

  // Get the next histogram in persistent data based on iterator.
  std::unique_ptr<HistogramBase> GetNextHistogram(Iterator* iter) {
    return GetNextHistogramWithIgnore(iter, 0);
  }

  // Create an iterator for going through all histograms in an allocator.
  void CreateIterator(Iterator* iter);

  // Allocate a new persistent histogram. The returned histogram will not
  // be able to be located by other allocators until it is "finalized".
  std::unique_ptr<HistogramBase> AllocateHistogram(
      HistogramType histogram_type,
      const std::string& name,
      int minimum,
      int maximum,
      const BucketRanges* bucket_ranges,
      int32_t flags,
      Reference* ref_ptr);

  // Finalize the creation of the histogram, making it available to other
  // processes if |registered| (as in: added to the StatisticsRecorder) is
  // True, forgetting it otherwise.
  void FinalizeHistogram(Reference ref, bool registered);

  // Create internal histograms for tracking memory use and allocation sizes
  // for allocator of |name| (which can simply be the result of Name()). This
  // is done seperately from construction for situations such as when the
  // histograms will be backed by memory provided by this very allocator.
  //
  // IMPORTANT: Callers must update tools/metrics/histograms/histograms.xml
  // with the following histograms:
  //    UMA.PersistentAllocator.name.Allocs
  //    UMA.PersistentAllocator.name.UsedPct
  void CreateTrackingHistograms(StringPiece name);
  void UpdateTrackingHistograms();

  // Manage a PersistentHistogramAllocator for globally storing histograms in
  // a space that can be persisted or shared between processes. There is only
  // ever one allocator for all such histograms created by a single process.
  // This takes ownership of the object and should be called as soon as
  // possible during startup to capture as many histograms as possible and
  // while operating single-threaded so there are no race-conditions.
  static void SetGlobalAllocator(
      std::unique_ptr<PersistentHistogramAllocator> allocator);
  static PersistentHistogramAllocator* GetGlobalAllocator();

  // This access to the persistent allocator is only for testing; it extracts
  // the current allocator completely. This allows easy creation of histograms
  // within persistent memory segments which can then be extracted and used
  // in other ways.
  static std::unique_ptr<PersistentHistogramAllocator>
  ReleaseGlobalAllocatorForTesting();

  // These helper methods perform SetGlobalAllocator() calls with allocators
  // of the specified type and parameters.
  static void CreateGlobalAllocatorOnPersistentMemory(
      void* base,
      size_t size,
      size_t page_size,
      uint64_t id,
      StringPiece name);
  static void CreateGlobalAllocatorOnLocalMemory(
      size_t size,
      uint64_t id,
      StringPiece name);
#if 0
  static void CreateGlobalAllocatorOnSharedMemory(
      size_t size,
      const SharedMemoryHandle& handle);
#endif

  // Import new histograms from the global PersistentHistogramAllocator. It's
  // possible for other processes to create histograms in the active memory
  // segment; this adds those to the internal list of known histograms to
  // avoid creating duplicates that would have to be merged during reporting.
  // Every call to this method resumes from the last entry it saw; it costs
  // nothing if nothing new has been added.
  static void ImportGlobalHistograms();

  // Histogram containing creation results. Visible for testing.
  static HistogramBase* GetCreateHistogramResultHistogram();

 private:
  // Enumerate possible creation results for reporting.
  enum CreateHistogramResultType {
    // Everything was fine.
    CREATE_HISTOGRAM_SUCCESS = 0,

    // Pointer to metadata was not valid.
    CREATE_HISTOGRAM_INVALID_METADATA_POINTER,

    // Histogram metadata was not valid.
    CREATE_HISTOGRAM_INVALID_METADATA,

    // Ranges information was not valid.
    CREATE_HISTOGRAM_INVALID_RANGES_ARRAY,

    // Counts information was not valid.
    CREATE_HISTOGRAM_INVALID_COUNTS_ARRAY,

    // Could not allocate histogram memory due to corruption.
    CREATE_HISTOGRAM_ALLOCATOR_CORRUPT,

    // Could not allocate histogram memory due to lack of space.
    CREATE_HISTOGRAM_ALLOCATOR_FULL,

    // Could not allocate histogram memory due to unknown error.
    CREATE_HISTOGRAM_ALLOCATOR_ERROR,

    // Histogram was of unknown type.
    CREATE_HISTOGRAM_UNKNOWN_TYPE,

    // Instance has detected a corrupt allocator (recorded only once).
    CREATE_HISTOGRAM_ALLOCATOR_NEWLY_CORRUPT,

    // Always keep this at the end.
    CREATE_HISTOGRAM_MAX
  };

  // The structure used to hold histogram data in persistent memory. It is
  // defined and used entirely within the .cc file.
  struct PersistentHistogramData;

  // Get the next histogram in persistent data based on iterator while
  // ignoring a particular reference if it is found.
  std::unique_ptr<HistogramBase> GetNextHistogramWithIgnore(Iterator* iter,
                                                            Reference ignore);

  // Create a histogram based on saved (persistent) information about it.
  std::unique_ptr<HistogramBase> CreateHistogram(
      PersistentHistogramData* histogram_data_ptr);

  // Record the result of a histogram creation.
  static void RecordCreateHistogramResult(CreateHistogramResultType result);

  // The memory allocator that provides the actual histogram storage.
  std::unique_ptr<PersistentMemoryAllocator> memory_allocator_;

  // A reference to the last-created histogram in the allocator, used to avoid
  // trying to import what was just created.
  subtle::AtomicWord last_created_ = 0;

  DISALLOW_COPY_AND_ASSIGN(PersistentHistogramAllocator);
};

}  // namespace base

#endif  // BASE_METRICS_HISTOGRAM_PERSISTENCE_H_
