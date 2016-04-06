// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/persistent_histogram_allocator.h"

#include <memory>

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/sparse_histogram.h"
#include "base/metrics/statistics_recorder.h"
#include "base/synchronization/lock.h"

// TODO(bcwhite): Order these methods to match the header file. The current
// order is only temporary in order to aid review of the transition from
// a non-class implementation.

namespace base {

namespace {

// Name of histogram for storing results of local operations.
const char kResultHistogram[] = "UMA.CreatePersistentHistogram.Result";

// Type identifiers used when storing in persistent memory so they can be
// identified during extraction; the first 4 bytes of the SHA1 of the name
// is used as a unique integer. A "version number" is added to the base
// so that, if the structure of that object changes, stored older versions
// will be safely ignored.
enum : uint32_t {
  kTypeIdHistogram   = 0xF1645910 + 2,  // SHA1(Histogram)   v2
  kTypeIdRangesArray = 0xBCEA225A + 1,  // SHA1(RangesArray) v1
  kTypeIdCountsArray = 0x53215530 + 1,  // SHA1(CountsArray) v1
};

// The current globally-active persistent allocator for all new histograms.
// The object held here will obviously not be destructed at process exit
// but that's best since PersistentMemoryAllocator objects (that underlie
// PersistentHistogramAllocator objects) are explicitly forbidden from doing
// anything essential at exit anyway due to the fact that they depend on data
// managed elsewhere and which could be destructed first.
PersistentHistogramAllocator* g_allocator;

// Take an array of range boundaries and create a proper BucketRanges object
// which is returned to the caller. A return of nullptr indicates that the
// passed boundaries are invalid.
std::unique_ptr<BucketRanges> CreateRangesFromData(
    HistogramBase::Sample* ranges_data,
    uint32_t ranges_checksum,
    size_t count) {
  // To avoid racy destruction at shutdown, the following may be leaked.
  std::unique_ptr<BucketRanges> ranges(new BucketRanges(count));
  DCHECK_EQ(count, ranges->size());
  for (size_t i = 0; i < count; ++i) {
    if (i > 0 && ranges_data[i] <= ranges_data[i - 1])
      return nullptr;
    ranges->set_range(i, ranges_data[i]);
  }

  ranges->ResetChecksum();
  if (ranges->checksum() != ranges_checksum)
    return nullptr;

  return ranges;
}

// Calculate the number of bytes required to store all of a histogram's
// "counts". This will return zero (0) if |bucket_count| is not valid.
size_t CalculateRequiredCountsBytes(size_t bucket_count) {
  // 2 because each "sample count" also requires a backup "logged count"
  // used for calculating the delta during snapshot operations.
  const size_t kBytesPerBucket = 2 * sizeof(HistogramBase::AtomicCount);

  // If the |bucket_count| is such that it would overflow the return type,
  // perhaps as the result of a malicious actor, then return zero to
  // indicate the problem to the caller.
  if (bucket_count > std::numeric_limits<size_t>::max() / kBytesPerBucket)
    return 0;

  return bucket_count * kBytesPerBucket;
}

}  // namespace

const Feature kPersistentHistogramsFeature{
  "PersistentHistograms", FEATURE_DISABLED_BY_DEFAULT
};

// This data will be held in persistent memory in order for processes to
// locate and use histograms created elsewhere.
struct PersistentHistogramAllocator::PersistentHistogramData {
  int32_t histogram_type;
  int32_t flags;
  int32_t minimum;
  int32_t maximum;
  uint32_t bucket_count;
  PersistentMemoryAllocator::Reference ranges_ref;
  uint32_t ranges_checksum;
  PersistentMemoryAllocator::Reference counts_ref;
  HistogramSamples::Metadata samples_metadata;
  HistogramSamples::Metadata logged_metadata;

  // Space for the histogram name will be added during the actual allocation
  // request. This must be the last field of the structure. A zero-size array
  // or a "flexible" array would be preferred but is not (yet) valid C++.
  char name[1];
};

PersistentHistogramAllocator::PersistentHistogramAllocator(
    std::unique_ptr<PersistentMemoryAllocator> memory)
    : memory_allocator_(std::move(memory)) {}

PersistentHistogramAllocator::~PersistentHistogramAllocator() {}

void PersistentHistogramAllocator::CreateIterator(Iterator* iter) {
  memory_allocator_->CreateIterator(&iter->memory_iter);
}

void PersistentHistogramAllocator::CreateTrackingHistograms(StringPiece name) {
  memory_allocator_->CreateTrackingHistograms(name);
}

void PersistentHistogramAllocator::UpdateTrackingHistograms() {
  memory_allocator_->UpdateTrackingHistograms();
}

// static
HistogramBase*
PersistentHistogramAllocator::GetCreateHistogramResultHistogram() {
  // Get the histogram in which create-results are stored. This is copied
  // almost exactly from the STATIC_HISTOGRAM_POINTER_BLOCK macro but with
  // added code to prevent recursion (a likely occurance because the creation
  // of a new a histogram can end up calling this.)
  static base::subtle::AtomicWord atomic_histogram_pointer = 0;
  HistogramBase* histogram_pointer =
      reinterpret_cast<HistogramBase*>(
          base::subtle::Acquire_Load(&atomic_histogram_pointer));
  if (!histogram_pointer) {
    // It's possible for multiple threads to make it here in parallel but
    // they'll always return the same result as there is a mutex in the Get.
    // The purpose of the "initialized" variable is just to ensure that
    // the same thread doesn't recurse which is also why it doesn't have
    // to be atomic.
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      if (g_allocator) {
        DLOG(WARNING) << "Creating the results-histogram inside persistent"
                      << " memory can cause future allocations to crash if"
                      << " that memory is ever released (for testing).";
      }

      histogram_pointer = LinearHistogram::FactoryGet(
          kResultHistogram, 1, CREATE_HISTOGRAM_MAX, CREATE_HISTOGRAM_MAX + 1,
          HistogramBase::kUmaTargetedHistogramFlag);
      base::subtle::Release_Store(
          &atomic_histogram_pointer,
          reinterpret_cast<base::subtle::AtomicWord>(histogram_pointer));
    }
  }
  return histogram_pointer;
}

// static
void PersistentHistogramAllocator::RecordCreateHistogramResult(
    CreateHistogramResultType result) {
  HistogramBase* result_histogram = GetCreateHistogramResultHistogram();
  if (result_histogram)
    result_histogram->Add(result);
}

// static
void PersistentHistogramAllocator::SetGlobalAllocator(
    std::unique_ptr<PersistentHistogramAllocator> allocator) {
  // Releasing or changing an allocator is extremely dangerous because it
  // likely has histograms stored within it. If the backing memory is also
  // also released, future accesses to those histograms will seg-fault.
  CHECK(!g_allocator);
  g_allocator = allocator.release();

  size_t existing = StatisticsRecorder::GetHistogramCount();
  DLOG_IF(WARNING, existing)
      << existing
      << " histograms were created before persistence was enabled.";
}

// static
PersistentHistogramAllocator*
PersistentHistogramAllocator::GetGlobalAllocator() {
  return g_allocator;
}

// static
std::unique_ptr<PersistentHistogramAllocator>
PersistentHistogramAllocator::ReleaseGlobalAllocatorForTesting() {
  PersistentHistogramAllocator* histogram_allocator = g_allocator;
  if (!histogram_allocator)
    return nullptr;
  PersistentMemoryAllocator* memory_allocator =
      histogram_allocator->memory_allocator();

  // Before releasing the memory, it's necessary to have the Statistics-
  // Recorder forget about the histograms contained therein; otherwise,
  // some operations will try to access them and the released memory.
  PersistentMemoryAllocator::Iterator iter;
  PersistentMemoryAllocator::Reference ref;
  uint32_t type_id;
  memory_allocator->CreateIterator(&iter);
  while ((ref = memory_allocator->GetNextIterable(&iter, &type_id)) != 0) {
    if (type_id == kTypeIdHistogram) {
      PersistentHistogramData* histogram_data =
          memory_allocator->GetAsObject<PersistentHistogramData>(
              ref, kTypeIdHistogram);
      DCHECK(histogram_data);
      StatisticsRecorder::ForgetHistogramForTesting(histogram_data->name);

      // If a test breaks here then a memory region containing a histogram
      // actively used by this code is being released back to the test.
      // If that memory segment were to be deleted, future calls to create
      // persistent histograms would crash. To avoid this, have the test call
      // the method GetCreateHistogramResultHistogram() *before* setting
      // the (temporary) memory allocator via SetGlobalAllocator() so that
      // histogram is instead allocated from the process heap.
      DCHECK_NE(kResultHistogram, histogram_data->name);
    }
  }

  g_allocator = nullptr;
  return WrapUnique(histogram_allocator);
};

// static
void PersistentHistogramAllocator::CreateGlobalAllocatorOnPersistentMemory(
    void* base,
    size_t size,
    size_t page_size,
    uint64_t id,
    StringPiece name) {
  SetGlobalAllocator(WrapUnique(new PersistentHistogramAllocator(
      WrapUnique(new PersistentMemoryAllocator(base, size, page_size, id,
                                                     name, false)))));
}

// static
void PersistentHistogramAllocator::CreateGlobalAllocatorOnLocalMemory(
    size_t size,
    uint64_t id,
    StringPiece name) {
  SetGlobalAllocator(WrapUnique(new PersistentHistogramAllocator(
      WrapUnique(new LocalPersistentMemoryAllocator(size, id, name)))));
}

#if 0
// static
void PersistentHistogramAllocator::CreateGlobalAllocatorOnSharedMemory(
    size_t size,
    const SharedMemoryHandle& handle) {
  std::unique_ptr<SharedMemory> shm(
      new SharedMemory(handle, /*readonly=*/false));
  if (!shm->Map(size)) {
    NOTREACHED();
    return;
  }

  SetGlobalAllocator(WrapUnique(new PersistentHistogramAllocator(
      WrapUnique(new SharedPersistentMemoryAllocator(
          std::move(shm), 0, StringPiece(), /*readonly=*/false)))));
}
#endif

// static
std::unique_ptr<HistogramBase> PersistentHistogramAllocator::CreateHistogram(
    PersistentHistogramData* histogram_data_ptr) {
  if (!histogram_data_ptr) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_INVALID_METADATA_POINTER);
    NOTREACHED();
    return nullptr;
  }

  // Sparse histograms are quite different so handle them as a special case.
  if (histogram_data_ptr->histogram_type == SPARSE_HISTOGRAM) {
    std::unique_ptr<HistogramBase> histogram =
        SparseHistogram::PersistentCreate(memory_allocator(),
                                          histogram_data_ptr->name,
                                          &histogram_data_ptr->samples_metadata,
                                          &histogram_data_ptr->logged_metadata);
    DCHECK(histogram);
    histogram->SetFlags(histogram_data_ptr->flags);
    RecordCreateHistogramResult(CREATE_HISTOGRAM_SUCCESS);
    return histogram;
  }

  // Copy the histogram_data to local storage because anything in persistent
  // memory cannot be trusted as it could be changed at any moment by a
  // malicious actor that shares access. The contents of histogram_data are
  // validated below; the local copy is to ensure that the contents cannot
  // be externally changed between validation and use.
  PersistentHistogramData histogram_data = *histogram_data_ptr;

  HistogramBase::Sample* ranges_data =
      memory_allocator_->GetAsObject<HistogramBase::Sample>(
          histogram_data.ranges_ref, kTypeIdRangesArray);

  const uint32_t max_buckets =
      std::numeric_limits<uint32_t>::max() / sizeof(HistogramBase::Sample);
  size_t required_bytes =
      (histogram_data.bucket_count + 1) * sizeof(HistogramBase::Sample);
  size_t allocated_bytes =
      memory_allocator_->GetAllocSize(histogram_data.ranges_ref);
  if (!ranges_data || histogram_data.bucket_count < 2 ||
      histogram_data.bucket_count >= max_buckets ||
      allocated_bytes < required_bytes) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_INVALID_RANGES_ARRAY);
    NOTREACHED();
    return nullptr;
  }

  std::unique_ptr<const BucketRanges> created_ranges =
      CreateRangesFromData(ranges_data, histogram_data.ranges_checksum,
                           histogram_data.bucket_count + 1);
  if (!created_ranges) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_INVALID_RANGES_ARRAY);
    NOTREACHED();
    return nullptr;
  }
  const BucketRanges* ranges =
      StatisticsRecorder::RegisterOrDeleteDuplicateRanges(
          created_ranges.release());

  HistogramBase::AtomicCount* counts_data =
      memory_allocator_->GetAsObject<HistogramBase::AtomicCount>(
          histogram_data.counts_ref, kTypeIdCountsArray);
  size_t counts_bytes =
      CalculateRequiredCountsBytes(histogram_data.bucket_count);
  if (!counts_data || counts_bytes == 0 ||
      memory_allocator_->GetAllocSize(histogram_data.counts_ref) <
          counts_bytes) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_INVALID_COUNTS_ARRAY);
    NOTREACHED();
    return nullptr;
  }

  // After the main "counts" array is a second array using for storing what
  // was previously logged. This is used to calculate the "delta" during
  // snapshot operations.
  HistogramBase::AtomicCount* logged_data =
      counts_data + histogram_data.bucket_count;

  std::string name(histogram_data_ptr->name);
  std::unique_ptr<HistogramBase> histogram;
  switch (histogram_data.histogram_type) {
    case HISTOGRAM:
      histogram = Histogram::PersistentCreate(
          name, histogram_data.minimum, histogram_data.maximum, ranges,
          counts_data, logged_data, histogram_data.bucket_count,
          &histogram_data_ptr->samples_metadata,
          &histogram_data_ptr->logged_metadata);
      DCHECK(histogram);
      break;
    case LINEAR_HISTOGRAM:
      histogram = LinearHistogram::PersistentCreate(
          name, histogram_data.minimum, histogram_data.maximum, ranges,
          counts_data, logged_data, histogram_data.bucket_count,
          &histogram_data_ptr->samples_metadata,
          &histogram_data_ptr->logged_metadata);
      DCHECK(histogram);
      break;
    case BOOLEAN_HISTOGRAM:
      histogram = BooleanHistogram::PersistentCreate(
          name, ranges, counts_data, logged_data,
          &histogram_data_ptr->samples_metadata,
          &histogram_data_ptr->logged_metadata);
      DCHECK(histogram);
      break;
    case CUSTOM_HISTOGRAM:
      histogram = CustomHistogram::PersistentCreate(
          name, ranges, counts_data, logged_data, histogram_data.bucket_count,
          &histogram_data_ptr->samples_metadata,
          &histogram_data_ptr->logged_metadata);
      DCHECK(histogram);
      break;
    default:
      NOTREACHED();
  }

  if (histogram) {
    DCHECK_EQ(histogram_data.histogram_type, histogram->GetHistogramType());
    histogram->SetFlags(histogram_data.flags);
    RecordCreateHistogramResult(CREATE_HISTOGRAM_SUCCESS);
  } else {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_UNKNOWN_TYPE);
  }

  return histogram;
}

std::unique_ptr<HistogramBase> PersistentHistogramAllocator::GetHistogram(
    Reference ref) {
  // Unfortunately, the histogram "pickle" methods cannot be used as part of
  // the persistance because the deserialization methods always create local
  // count data (while these must reference the persistent counts) and always
  // add it to the local list of known histograms (while these may be simple
  // references to histograms in other processes).
  PersistentHistogramData* histogram_data =
      memory_allocator_->GetAsObject<PersistentHistogramData>(
          ref, kTypeIdHistogram);
  size_t length = memory_allocator_->GetAllocSize(ref);
  if (!histogram_data ||
      reinterpret_cast<char*>(histogram_data)[length - 1] != '\0') {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_INVALID_METADATA);
    NOTREACHED();
    return nullptr;
  }
  return CreateHistogram(histogram_data);
}

std::unique_ptr<HistogramBase>
PersistentHistogramAllocator::GetNextHistogramWithIgnore(Iterator* iter,
                                                         Reference ignore) {
  PersistentMemoryAllocator::Reference ref;
  uint32_t type_id;
  while ((ref = memory_allocator_->GetNextIterable(&iter->memory_iter,
                                                   &type_id)) != 0) {
    if (ref == ignore)
      continue;
    if (type_id == kTypeIdHistogram)
      return GetHistogram(ref);
  }
  return nullptr;
}

void PersistentHistogramAllocator::FinalizeHistogram(Reference ref,
                                                     bool registered) {
  // If the created persistent histogram was registered then it needs to
  // be marked as "iterable" in order to be found by other processes.
  if (registered)
    memory_allocator_->MakeIterable(ref);
  // If it wasn't registered then a race condition must have caused
  // two to be created. The allocator does not support releasing the
  // acquired memory so just change the type to be empty.
  else
    memory_allocator_->SetType(ref, 0);
}

std::unique_ptr<HistogramBase> PersistentHistogramAllocator::AllocateHistogram(
    HistogramType histogram_type,
    const std::string& name,
    int minimum,
    int maximum,
    const BucketRanges* bucket_ranges,
    int32_t flags,
    Reference* ref_ptr) {
  // If the allocator is corrupt, don't waste time trying anything else.
  // This also allows differentiating on the dashboard between allocations
  // failed due to a corrupt allocator and the number of process instances
  // with one, the latter being idicated by "newly corrupt", below.
  if (memory_allocator_->IsCorrupt()) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_ALLOCATOR_CORRUPT);
    return nullptr;
  }

  // Create the metadata necessary for a persistent sparse histogram. This
  // is done first because it is a small subset of what is required for
  // other histograms.
  PersistentMemoryAllocator::Reference histogram_ref =
      memory_allocator_->Allocate(
          offsetof(PersistentHistogramData, name) + name.length() + 1,
          kTypeIdHistogram);
  PersistentHistogramData* histogram_data =
      memory_allocator_->GetAsObject<PersistentHistogramData>(histogram_ref,
                                                              kTypeIdHistogram);
  if (histogram_data) {
    memcpy(histogram_data->name, name.c_str(), name.size() + 1);
    histogram_data->histogram_type = histogram_type;
    histogram_data->flags = flags | HistogramBase::kIsPersistent;
  }

  // Create the remaining metadata necessary for regular histograms.
  if (histogram_type != SPARSE_HISTOGRAM) {
    size_t bucket_count = bucket_ranges->bucket_count();
    size_t counts_bytes = CalculateRequiredCountsBytes(bucket_count);
    if (counts_bytes == 0) {
      // |bucket_count| was out-of-range.
      NOTREACHED();
      return nullptr;
    }

    size_t ranges_bytes = (bucket_count + 1) * sizeof(HistogramBase::Sample);
    PersistentMemoryAllocator::Reference counts_ref =
        memory_allocator_->Allocate(counts_bytes, kTypeIdCountsArray);
    PersistentMemoryAllocator::Reference ranges_ref =
        memory_allocator_->Allocate(ranges_bytes, kTypeIdRangesArray);
    HistogramBase::Sample* ranges_data =
        memory_allocator_->GetAsObject<HistogramBase::Sample>(
            ranges_ref, kTypeIdRangesArray);

    // Only continue here if all allocations were successful. If they weren't,
    // there is no way to free the space but that's not really a problem since
    // the allocations only fail because the space is full or corrupt and so
    // any future attempts will also fail.
    if (counts_ref && ranges_data && histogram_data) {
      for (size_t i = 0; i < bucket_ranges->size(); ++i)
        ranges_data[i] = bucket_ranges->range(i);

      histogram_data->minimum = minimum;
      histogram_data->maximum = maximum;
      // |bucket_count| must fit within 32-bits or the allocation of the counts
      // array would have failed for being too large; the allocator supports
      // less than 4GB total size.
      histogram_data->bucket_count = static_cast<uint32_t>(bucket_count);
      histogram_data->ranges_ref = ranges_ref;
      histogram_data->ranges_checksum = bucket_ranges->checksum();
      histogram_data->counts_ref = counts_ref;
    } else {
      histogram_data = nullptr;  // Clear this for proper handling below.
    }
  }

  if (histogram_data) {
    // Create the histogram using resources in persistent memory. This ends up
    // resolving the "ref" values stored in histogram_data instad of just
    // using what is already known above but avoids duplicating the switch
    // statement here and serves as a double-check that everything is
    // correct before commiting the new histogram to persistent space.
    std::unique_ptr<HistogramBase> histogram = CreateHistogram(histogram_data);
    DCHECK(histogram);
    if (ref_ptr != nullptr)
      *ref_ptr = histogram_ref;

    // By storing the reference within the allocator to this histogram, the
    // next import (which will happen before the next histogram creation)
    // will know to skip it. See also the comment in ImportGlobalHistograms().
    subtle::NoBarrier_Store(&last_created_, histogram_ref);
    return histogram;
  }

  CreateHistogramResultType result;
  if (memory_allocator_->IsCorrupt()) {
    RecordCreateHistogramResult(CREATE_HISTOGRAM_ALLOCATOR_NEWLY_CORRUPT);
    result = CREATE_HISTOGRAM_ALLOCATOR_CORRUPT;
  } else if (memory_allocator_->IsFull()) {
    result = CREATE_HISTOGRAM_ALLOCATOR_FULL;
  } else {
    result = CREATE_HISTOGRAM_ALLOCATOR_ERROR;
  }
  RecordCreateHistogramResult(result);
  NOTREACHED() << "error=" << result;

  return nullptr;
}

// static
void PersistentHistogramAllocator::ImportGlobalHistograms() {
  // The lock protects against concurrent access to the iterator and is created
  // in a thread-safe manner when needed.
  static base::LazyInstance<base::Lock>::Leaky lock = LAZY_INSTANCE_INITIALIZER;

  if (g_allocator) {
    // TODO(bcwhite): Investigate a lock-free, thread-safe iterator.
    base::AutoLock auto_lock(lock.Get());

    // Each call resumes from where it last left off so a persistant iterator
    // is needed. This class has a constructor so even the definition has to
    // be protected by the lock in order to be thread-safe.
    static Iterator iter;
    if (iter.is_clear())
      g_allocator->CreateIterator(&iter);

    // Skip the import if it's the histogram that was last created. Should a
    // race condition cause the "last created" to be overwritten before it
    // is recognized here then the histogram will be created and be ignored
    // when it is detected as a duplicate by the statistics-recorder. This
    // simple check reduces the time of creating persistent histograms by
    // about 40%.
    Reference last_created =
        subtle::NoBarrier_Load(&g_allocator->last_created_);

    while (true) {
      std::unique_ptr<HistogramBase> histogram =
          g_allocator->GetNextHistogramWithIgnore(&iter, last_created);
      if (!histogram)
        break;
      StatisticsRecorder::RegisterOrDeleteDuplicate(histogram.release());
    }
  }
}

}  // namespace base
