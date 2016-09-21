// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/persistent_histogram_allocator.h"

#include <memory>

#include "base/files/file_path.h"
#if 0
#include "base/files/file_util.h"
#include "base/files/important_file_writer.h"
#include "base/files/memory_mapped_file.h"
#endif
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/persistent_sample_map.h"
#include "base/metrics/sparse_histogram.h"
#include "base/metrics/statistics_recorder.h"
#include "base/pickle.h"
#include "base/synchronization/lock.h"

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
// GlobalHistogramAllocator objects) are explicitly forbidden from doing
// anything essential at exit anyway due to the fact that they depend on data
// managed elsewhere and which could be destructed first.
GlobalHistogramAllocator* g_allocator = nullptr;

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


PersistentSparseHistogramDataManager::PersistentSparseHistogramDataManager(
    PersistentMemoryAllocator* allocator)
    : allocator_(allocator), record_iterator_(allocator) {}

PersistentSparseHistogramDataManager::~PersistentSparseHistogramDataManager() {}

PersistentSampleMapRecords*
PersistentSparseHistogramDataManager::UseSampleMapRecords(uint64_t id,
                                                          const void* user) {
  base::AutoLock auto_lock(lock_);
  return GetSampleMapRecordsWhileLocked(id)->Acquire(user);
}

PersistentSampleMapRecords*
PersistentSparseHistogramDataManager::GetSampleMapRecordsWhileLocked(
    uint64_t id) {
  lock_.AssertAcquired();

  auto found = sample_records_.find(id);
  if (found != sample_records_.end())
    return found->second.get();

  std::unique_ptr<PersistentSampleMapRecords>& samples = sample_records_[id];
  samples = MakeUnique<PersistentSampleMapRecords>(this, id);
  return samples.get();
}

bool PersistentSparseHistogramDataManager::LoadRecords(
    PersistentSampleMapRecords* sample_map_records) {
  // DataManager must be locked in order to access the found_ field of any
  // PersistentSampleMapRecords object.
  base::AutoLock auto_lock(lock_);
  bool found = false;

  // If there are already "found" entries for the passed object, move them.
  if (!sample_map_records->found_.empty()) {
    sample_map_records->records_.reserve(sample_map_records->records_.size() +
                                         sample_map_records->found_.size());
    sample_map_records->records_.insert(sample_map_records->records_.end(),
                                        sample_map_records->found_.begin(),
                                        sample_map_records->found_.end());
    sample_map_records->found_.clear();
    found = true;
  }

  // Acquiring a lock is a semi-expensive operation so load some records with
  // each call. More than this number may be loaded if it takes longer to
  // find at least one matching record for the passed object.
  const int kMinimumNumberToLoad = 10;
  const uint64_t match_id = sample_map_records->sample_map_id_;

  // Loop while no enty is found OR we haven't yet loaded the minimum number.
  // This will continue reading even after a match is found.
  for (int count = 0; !found || count < kMinimumNumberToLoad; ++count) {
    // Get the next sample-record. The iterator will always resume from where
    // it left off even if it previously had nothing further to return.
    uint64_t found_id;
    PersistentMemoryAllocator::Reference ref =
        PersistentSampleMap::GetNextPersistentRecord(record_iterator_,
                                                     &found_id);

    // Stop immediately if there are none.
    if (!ref)
      break;

    // The sample-record could be for any sparse histogram. Add the reference
    // to the appropriate collection for later use.
    if (found_id == match_id) {
      sample_map_records->records_.push_back(ref);
      found = true;
    } else {
      PersistentSampleMapRecords* samples =
          GetSampleMapRecordsWhileLocked(found_id);
      DCHECK(samples);
      samples->found_.push_back(ref);
    }
  }

  return found;
}


PersistentSampleMapRecords::PersistentSampleMapRecords(
    PersistentSparseHistogramDataManager* data_manager,
    uint64_t sample_map_id)
    : data_manager_(data_manager), sample_map_id_(sample_map_id) {}

PersistentSampleMapRecords::~PersistentSampleMapRecords() {}

PersistentSampleMapRecords* PersistentSampleMapRecords::Acquire(
    const void* user) {
  DCHECK(!user_);
  user_ = user;
  seen_ = 0;
  return this;
}

void PersistentSampleMapRecords::Release(const void* user) {
  DCHECK_EQ(user_, user);
  user_ = nullptr;
}

PersistentMemoryAllocator::Reference PersistentSampleMapRecords::GetNext() {
  DCHECK(user_);

  // If there are no unseen records, lock and swap in all the found ones.
  if (records_.size() == seen_) {
    if (!data_manager_->LoadRecords(this))
      return false;
  }

  // Return the next record. Records *must* be returned in the same order
  // they are found in the persistent memory in order to ensure that all
  // objects using this data always have the same state. Race conditions
  // can cause duplicate records so using the "first found" is the only
  // guarantee that all objects always access the same one.
  DCHECK_LT(seen_, records_.size());
  return records_[seen_++];
}

PersistentMemoryAllocator::Reference PersistentSampleMapRecords::CreateNew(
    HistogramBase::Sample value) {
  return PersistentSampleMap::CreatePersistentRecord(data_manager_->allocator_,
                                                     sample_map_id_, value);
}


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

PersistentHistogramAllocator::Iterator::Iterator(
    PersistentHistogramAllocator* allocator)
    : allocator_(allocator), memory_iter_(allocator->memory_allocator()) {}

std::unique_ptr<HistogramBase>
PersistentHistogramAllocator::Iterator::GetNextWithIgnore(Reference ignore) {
  PersistentMemoryAllocator::Reference ref;
  while ((ref = memory_iter_.GetNextOfType(kTypeIdHistogram)) != 0) {
    if (ref != ignore)
      return allocator_->GetHistogram(ref);
  }
  return nullptr;
}


PersistentHistogramAllocator::PersistentHistogramAllocator(
    std::unique_ptr<PersistentMemoryAllocator> memory)
    : memory_allocator_(std::move(memory)),
      sparse_histogram_data_manager_(memory_allocator_.get()) {}

PersistentHistogramAllocator::~PersistentHistogramAllocator() {}

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
    // will know to skip it.
    // See also the comment in ImportHistogramsToStatisticsRecorder().
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
    memory_allocator_->ChangeType(ref, 0, kTypeIdHistogram);
}

void PersistentHistogramAllocator::MergeHistogramDeltaToStatisticsRecorder(
    HistogramBase* histogram) {
  DCHECK(histogram);

  HistogramBase* existing = GetOrCreateStatisticsRecorderHistogram(histogram);
  if (!existing) {
    // The above should never fail but if it does, no real harm is done.
    // The data won't be merged but it also won't be recorded as merged
    // so a future try, if successful, will get what was missed. If it
    // continues to fail, some metric data will be lost but that is better
    // than crashing.
    NOTREACHED();
    return;
  }

  // Merge the delta from the passed object to the one in the SR.
  existing->AddSamples(*histogram->SnapshotDelta());
}

void PersistentHistogramAllocator::MergeHistogramFinalDeltaToStatisticsRecorder(
    const HistogramBase* histogram) {
  DCHECK(histogram);

  HistogramBase* existing = GetOrCreateStatisticsRecorderHistogram(histogram);
  if (!existing) {
    // The above should never fail but if it does, no real harm is done.
    // Some metric data will be lost but that is better than crashing.
    NOTREACHED();
    return;
  }

  // Merge the delta from the passed object to the one in the SR.
  existing->AddSamples(*histogram->SnapshotFinalDelta());
}

PersistentSampleMapRecords* PersistentHistogramAllocator::UseSampleMapRecords(
    uint64_t id,
    const void* user) {
  return sparse_histogram_data_manager_.UseSampleMapRecords(id, user);
}

void PersistentHistogramAllocator::CreateTrackingHistograms(StringPiece name) {
  memory_allocator_->CreateTrackingHistograms(name);
}

void PersistentHistogramAllocator::UpdateTrackingHistograms() {
  memory_allocator_->UpdateTrackingHistograms();
}

void PersistentHistogramAllocator::ClearLastCreatedReferenceForTesting() {
  subtle::NoBarrier_Store(&last_created_, 0);
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
// Don't log in release-with-asserts builds, otherwise the test_installer step
// fails because this code writes to a log file before the installer code had a
// chance to set the log file's location.
#if !defined(DCHECK_ALWAYS_ON)
        DLOG(WARNING) << "Creating the results-histogram inside persistent"
                      << " memory can cause future allocations to crash if"
                      << " that memory is ever released (for testing).";
#endif
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
        SparseHistogram::PersistentCreate(this, histogram_data_ptr->name,
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

HistogramBase*
PersistentHistogramAllocator::GetOrCreateStatisticsRecorderHistogram(
    const HistogramBase* histogram) {
  // This should never be called on the global histogram allocator as objects
  // created there are already within the global statistics recorder.
  DCHECK_NE(g_allocator, this);
  DCHECK(histogram);

  HistogramBase* existing =
      StatisticsRecorder::FindHistogram(histogram->histogram_name());
  if (existing)
    return existing;

  // Adding the passed histogram to the SR would cause a problem if the
  // allocator that holds it eventually goes away. Instead, create a new
  // one from a serialized version.
  base::Pickle pickle;
  if (!histogram->SerializeInfo(&pickle))
    return nullptr;
  PickleIterator iter(pickle);
  existing = DeserializeHistogramInfo(&iter);
  if (!existing)
    return nullptr;

  // Make sure there is no "serialization" flag set.
  DCHECK_EQ(0, existing->flags() & HistogramBase::kIPCSerializationSourceFlag);
  // Record the newly created histogram in the SR.
  return StatisticsRecorder::RegisterOrDeleteDuplicate(existing);
}

// static
void PersistentHistogramAllocator::RecordCreateHistogramResult(
    CreateHistogramResultType result) {
  HistogramBase* result_histogram = GetCreateHistogramResultHistogram();
  if (result_histogram)
    result_histogram->Add(result);
}

GlobalHistogramAllocator::~GlobalHistogramAllocator() {}

// static
void GlobalHistogramAllocator::CreateWithPersistentMemory(
    void* base,
    size_t size,
    size_t page_size,
    uint64_t id,
    StringPiece name) {
  Set(WrapUnique(
      new GlobalHistogramAllocator(MakeUnique<PersistentMemoryAllocator>(
          base, size, page_size, id, name, false))));
}

// static
void GlobalHistogramAllocator::CreateWithLocalMemory(
    size_t size,
    uint64_t id,
    StringPiece name) {
  Set(WrapUnique(new GlobalHistogramAllocator(
      MakeUnique<LocalPersistentMemoryAllocator>(size, id, name))));
}

#if 0
#if !defined(OS_NACL)
// static
void GlobalHistogramAllocator::CreateWithFile(
    const FilePath& file_path,
    size_t size,
    uint64_t id,
    StringPiece name) {
  bool exists = PathExists(file_path);
  File file(
      file_path, File::FLAG_OPEN_ALWAYS | File::FLAG_SHARE_DELETE |
                 File::FLAG_READ | File::FLAG_WRITE);

  std::unique_ptr<MemoryMappedFile> mmfile(new MemoryMappedFile());
  if (exists) {
    mmfile->Initialize(std::move(file), MemoryMappedFile::READ_WRITE);
  } else {
    mmfile->Initialize(std::move(file), {0, static_cast<int64_t>(size)},
                       MemoryMappedFile::READ_WRITE_EXTEND);
  }
  if (!mmfile->IsValid() ||
      !FilePersistentMemoryAllocator::IsFileAcceptable(*mmfile, true)) {
    NOTREACHED();
    return;
  }

  Set(WrapUnique(
      new GlobalHistogramAllocator(MakeUnique<FilePersistentMemoryAllocator>(
          std::move(mmfile), size, id, name, false))));
}
#endif

// static
void GlobalHistogramAllocator::CreateWithSharedMemory(
    std::unique_ptr<SharedMemory> memory,
    size_t size,
    uint64_t id,
    StringPiece name) {
  if ((!memory->memory() && !memory->Map(size)) ||
      !SharedPersistentMemoryAllocator::IsSharedMemoryAcceptable(*memory)) {
    NOTREACHED();
    return;
  }

  DCHECK_LE(memory->mapped_size(), size);
  Set(WrapUnique(
      new GlobalHistogramAllocator(MakeUnique<SharedPersistentMemoryAllocator>(
          std::move(memory), 0, StringPiece(), /*readonly=*/false))));
}

// static
void GlobalHistogramAllocator::CreateWithSharedMemoryHandle(
    const SharedMemoryHandle& handle,
    size_t size) {
  std::unique_ptr<SharedMemory> shm(
      new SharedMemory(handle, /*readonly=*/false));
  if (!shm->Map(size) ||
      !SharedPersistentMemoryAllocator::IsSharedMemoryAcceptable(*shm)) {
    NOTREACHED();
    return;
  }

  Set(WrapUnique(
      new GlobalHistogramAllocator(MakeUnique<SharedPersistentMemoryAllocator>(
          std::move(shm), 0, StringPiece(), /*readonly=*/false))));
}
#endif

// static
void GlobalHistogramAllocator::Set(
    std::unique_ptr<GlobalHistogramAllocator> allocator) {
  // Releasing or changing an allocator is extremely dangerous because it
  // likely has histograms stored within it. If the backing memory is also
  // also released, future accesses to those histograms will seg-fault.
  CHECK(!g_allocator);
  g_allocator = allocator.release();
  size_t existing = StatisticsRecorder::GetHistogramCount();

  DVLOG_IF(1, existing)
      << existing << " histograms were created before persistence was enabled.";
}

// static
GlobalHistogramAllocator* GlobalHistogramAllocator::Get() {
  return g_allocator;
}

// static
std::unique_ptr<GlobalHistogramAllocator>
GlobalHistogramAllocator::ReleaseForTesting() {
  GlobalHistogramAllocator* histogram_allocator = g_allocator;
  if (!histogram_allocator)
    return nullptr;
  PersistentMemoryAllocator* memory_allocator =
      histogram_allocator->memory_allocator();

  // Before releasing the memory, it's necessary to have the Statistics-
  // Recorder forget about the histograms contained therein; otherwise,
  // some operations will try to access them and the released memory.
  PersistentMemoryAllocator::Iterator iter(memory_allocator);
  PersistentMemoryAllocator::Reference ref;
  while ((ref = iter.GetNextOfType(kTypeIdHistogram)) != 0) {
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

  g_allocator = nullptr;
  return WrapUnique(histogram_allocator);
};

void GlobalHistogramAllocator::SetPersistentLocation(const FilePath& location) {
  persistent_location_ = location;
}

const FilePath& GlobalHistogramAllocator::GetPersistentLocation() const {
  return persistent_location_;
}

bool GlobalHistogramAllocator::WriteToPersistentLocation() {
#if 0
#if defined(OS_NACL)
  // NACL doesn't support file operations, including ImportantFileWriter.
  NOTREACHED();
  return false;
#else
  // Stop if no destination is set.
  if (persistent_location_.empty()) {
    NOTREACHED() << "Could not write \"" << Name() << "\" persistent histograms"
                 << " to file because no location was set.";
    return false;
  }

  StringPiece contents(static_cast<const char*>(data()), used());
  if (!ImportantFileWriter::WriteFileAtomically(persistent_location_,
                                                contents)) {
    LOG(ERROR) << "Could not write \"" << Name() << "\" persistent histograms"
               << " to file: " << persistent_location_.value();
    return false;
  }

  return true;
#endif
#else
  // libquic does not support this
  return false;
#endif
}

GlobalHistogramAllocator::GlobalHistogramAllocator(
    std::unique_ptr<PersistentMemoryAllocator> memory)
    : PersistentHistogramAllocator(std::move(memory)),
      import_iterator_(this) {}

void GlobalHistogramAllocator::ImportHistogramsToStatisticsRecorder() {
  // Skip the import if it's the histogram that was last created. Should a
  // race condition cause the "last created" to be overwritten before it
  // is recognized here then the histogram will be created and be ignored
  // when it is detected as a duplicate by the statistics-recorder. This
  // simple check reduces the time of creating persistent histograms by
  // about 40%.
  Reference record_to_ignore = last_created();

  // There is no lock on this because the iterator is lock-free while still
  // guaranteed to only return each entry only once. The StatisticsRecorder
  // has its own lock so the Register operation is safe.
  while (true) {
    std::unique_ptr<HistogramBase> histogram =
        import_iterator_.GetNextWithIgnore(record_to_ignore);
    if (!histogram)
      break;
    StatisticsRecorder::RegisterOrDeleteDuplicate(histogram.release());
  }
}

}  // namespace base
