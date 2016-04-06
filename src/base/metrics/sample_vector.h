// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// SampleVector implements HistogramSamples interface. It is used by all
// Histogram based classes to store samples.

#ifndef BASE_METRICS_SAMPLE_VECTOR_H_
#define BASE_METRICS_SAMPLE_VECTOR_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <vector>

#include "base/compiler_specific.h"
#include "base/gtest_prod_util.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/histogram_samples.h"

namespace base {

class BucketRanges;

class BASE_EXPORT SampleVector : public HistogramSamples {
 public:
  explicit SampleVector(const BucketRanges* bucket_ranges);
  SampleVector(uint64_t id, const BucketRanges* bucket_ranges);
  SampleVector(uint64_t id,
               HistogramBase::AtomicCount* counts,
               size_t counts_size,
               Metadata* meta,
               const BucketRanges* bucket_ranges);
  ~SampleVector() override;

  // HistogramSamples implementation:
  void Accumulate(HistogramBase::Sample value,
                  HistogramBase::Count count) override;
  HistogramBase::Count GetCount(HistogramBase::Sample value) const override;
  HistogramBase::Count TotalCount() const override;
  std::unique_ptr<SampleCountIterator> Iterator() const override;

  // Get count of a specific bucket.
  HistogramBase::Count GetCountAtIndex(size_t bucket_index) const;

 protected:
  bool AddSubtractImpl(
      SampleCountIterator* iter,
      HistogramSamples::Operator op) override;  // |op| is ADD or SUBTRACT.

  virtual size_t GetBucketIndex(HistogramBase::Sample value) const;

 private:
  FRIEND_TEST_ALL_PREFIXES(HistogramTest, CorruptSampleCounts);
  FRIEND_TEST_ALL_PREFIXES(SharedHistogramTest, CorruptSampleCounts);

  // In the case where this class manages the memory, here it is.
  std::vector<HistogramBase::AtomicCount> local_counts_;

  // These are raw pointers rather than objects for flexibility. The actual
  // memory is either managed by local_counts_ above or by an external object
  // and passed in directly.
  HistogramBase::AtomicCount* counts_;
  size_t counts_size_;

  // Shares the same BucketRanges with Histogram object.
  const BucketRanges* const bucket_ranges_;

  DISALLOW_COPY_AND_ASSIGN(SampleVector);
};

class BASE_EXPORT SampleVectorIterator : public SampleCountIterator {
 public:
  SampleVectorIterator(const std::vector<HistogramBase::AtomicCount>* counts,
                       const BucketRanges* bucket_ranges);
  SampleVectorIterator(const HistogramBase::AtomicCount* counts,
                       size_t counts_size,
                       const BucketRanges* bucket_ranges);
  ~SampleVectorIterator() override;

  // SampleCountIterator implementation:
  bool Done() const override;
  void Next() override;
  void Get(HistogramBase::Sample* min,
           HistogramBase::Sample* max,
           HistogramBase::Count* count) const override;

  // SampleVector uses predefined buckets, so iterator can return bucket index.
  bool GetBucketIndex(size_t* index) const override;

 private:
  void SkipEmptyBuckets();

  const HistogramBase::AtomicCount* counts_;
  size_t counts_size_;
  const BucketRanges* bucket_ranges_;

  size_t index_;
};

}  // namespace base

#endif  // BASE_METRICS_SAMPLE_VECTOR_H_
