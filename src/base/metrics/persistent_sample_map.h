// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// PersistentSampleMap implements HistogramSamples interface. It is used
// by the SparseHistogram class to store samples in persistent memory which
// allows it to be shared between processes or live across restarts.

#ifndef BASE_METRICS_PERSISTENT_SAMPLE_MAP_H_
#define BASE_METRICS_PERSISTENT_SAMPLE_MAP_H_

#include <stdint.h>

#include <map>
#include <memory>

#include "base/compiler_specific.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_samples.h"
#include "base/metrics/persistent_memory_allocator.h"

namespace base {

// The logic here is similar to that of SampleMap but with different data
// structures. Changes here likely need to be duplicated there.
class BASE_EXPORT PersistentSampleMap : public HistogramSamples {
 public:
  PersistentSampleMap(uint64_t id,
                      PersistentMemoryAllocator* allocator,
                      Metadata* meta);
  ~PersistentSampleMap() override;

  // HistogramSamples:
  void Accumulate(HistogramBase::Sample value,
                  HistogramBase::Count count) override;
  HistogramBase::Count GetCount(HistogramBase::Sample value) const override;
  HistogramBase::Count TotalCount() const override;
  std::unique_ptr<SampleCountIterator> Iterator() const override;

 protected:
  // Performs arithemetic. |op| is ADD or SUBTRACT.
  bool AddSubtractImpl(SampleCountIterator* iter, Operator op) override;

  // Gets a pointer to a "count" corresponding to a given |value|. Returns NULL
  // if sample does not exist.
  HistogramBase::Count* GetSampleCountStorage(HistogramBase::Sample value);

  // Gets a pointer to a "count" corresponding to a given |value|, creating
  // the sample (initialized to zero) if it does not already exists.
  HistogramBase::Count* GetOrCreateSampleCountStorage(
      HistogramBase::Sample value);

 private:
  enum : HistogramBase::Sample { kAllSamples = -1 };

  // Imports samples from persistent memory by iterating over all sample
  // records found therein, adding them to the sample_counts_ map. If a
  // count for the sample |until_value| is found, stop the import and return
  // a pointer to that counter. If that value is not found, null will be
  // returned after all currently available samples have been loaded. Pass
  // kAllSamples to force the importing of all available samples.
  HistogramBase::Count* ImportSamples(HistogramBase::Sample until_value);

  // All created/loaded sample values and their associated counts. The storage
  // for the actual Count numbers is owned by the |allocator_|.
  std::map<HistogramBase::Sample, HistogramBase::Count*> sample_counts_;

  // The persistent memory allocator holding samples and an iterator through it.
  PersistentMemoryAllocator* allocator_;
  PersistentMemoryAllocator::Iterator sample_iter_;

  DISALLOW_COPY_AND_ASSIGN(PersistentSampleMap);
};

}  // namespace base

#endif  // BASE_METRICS_PERSISTENT_SAMPLE_MAP_H_
