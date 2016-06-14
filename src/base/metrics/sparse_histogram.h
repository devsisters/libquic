// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_SPARSE_HISTOGRAM_H_
#define BASE_METRICS_SPARSE_HISTOGRAM_H_

#include <stddef.h>
#include <stdint.h>

#include <map>
#include <memory>
#include <string>

#include "base/base_export.h"
#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/sample_map.h"
#include "base/synchronization/lock.h"

namespace base {

// Sparse histograms are well suited for recording counts of exact sample values
// that are sparsely distributed over a large range.
//
// The implementation uses a lock and a map, whereas other histogram types use a
// vector and no lock. It is thus more costly to add values to, and each value
// stored has more overhead, compared to the other histogram types. However it
// may be more efficient in memory if the total number of sample values is small
// compared to the range of their values.
//
// UMA_HISTOGRAM_ENUMERATION would be better suited for a smaller range of
// enumerations that are (nearly) contiguous. Also for code that is expected to
// run often or in a tight loop.
//
// UMA_HISTOGRAM_SPARSE_SLOWLY is good for sparsely distributed and or
// infrequently recorded values.
//
// For instance, Sqlite.Version.* are SPARSE because for any given database,
// there's going to be exactly one version logged, meaning no gain to having a
// pre-allocated vector of slots once the fleet gets to version 4 or 5 or 10.
// Likewise Sqlite.Error.* are SPARSE, because most databases generate few or no
// errors and there are large gaps in the set of possible errors.
#define UMA_HISTOGRAM_SPARSE_SLOWLY(name, sample) \
    do { \
      base::HistogramBase* histogram = base::SparseHistogram::FactoryGet( \
          name, base::HistogramBase::kUmaTargetedHistogramFlag); \
      histogram->Add(sample); \
    } while (0)

class HistogramSamples;
class PersistentHistogramAllocator;

class BASE_EXPORT SparseHistogram : public HistogramBase {
 public:
  // If there's one with same name, return the existing one. If not, create a
  // new one.
  static HistogramBase* FactoryGet(const std::string& name, int32_t flags);

  // Create a histogram using data in persistent storage. The allocator must
  // live longer than the created sparse histogram.
  static std::unique_ptr<HistogramBase> PersistentCreate(
      PersistentHistogramAllocator* allocator,
      const std::string& name,
      HistogramSamples::Metadata* meta,
      HistogramSamples::Metadata* logged_meta);

  ~SparseHistogram() override;

  // HistogramBase implementation:
  uint64_t name_hash() const override;
  HistogramType GetHistogramType() const override;
  bool HasConstructionArguments(Sample expected_minimum,
                                Sample expected_maximum,
                                uint32_t expected_bucket_count) const override;
  void Add(Sample value) override;
  void AddCount(Sample value, int count) override;
  void AddSamples(const HistogramSamples& samples) override;
  bool AddSamplesFromPickle(base::PickleIterator* iter) override;
  std::unique_ptr<HistogramSamples> SnapshotSamples() const override;
  std::unique_ptr<HistogramSamples> SnapshotDelta() override;
  std::unique_ptr<HistogramSamples> SnapshotFinalDelta() const override;
  void WriteHTMLGraph(std::string* output) const override;
  void WriteAscii(std::string* output) const override;

 protected:
  // HistogramBase implementation:
  bool SerializeInfoImpl(base::Pickle* pickle) const override;

 private:
  // Clients should always use FactoryGet to create SparseHistogram.
  explicit SparseHistogram(const std::string& name);

  SparseHistogram(PersistentHistogramAllocator* allocator,
                  const std::string& name,
                  HistogramSamples::Metadata* meta,
                  HistogramSamples::Metadata* logged_meta);

  friend BASE_EXPORT HistogramBase* DeserializeHistogramInfo(
      base::PickleIterator* iter);
  static HistogramBase* DeserializeInfoImpl(base::PickleIterator* iter);

  void GetParameters(DictionaryValue* params) const override;
  void GetCountAndBucketData(Count* count,
                             int64_t* sum,
                             ListValue* buckets) const override;

  // Helpers for emitting Ascii graphic.  Each method appends data to output.
  void WriteAsciiImpl(bool graph_it,
                      const std::string& newline,
                      std::string* output) const;

  // Write a common header message describing this histogram.
  void WriteAsciiHeader(const Count total_count,
                        std::string* output) const;

  // For constuctor calling.
  friend class SparseHistogramTest;

  // Protects access to |samples_|.
  mutable base::Lock lock_;

  // Flag to indicate if PrepareFinalDelta has been previously called.
  mutable bool final_delta_created_ = false;

  std::unique_ptr<HistogramSamples> samples_;
  std::unique_ptr<HistogramSamples> logged_samples_;

  DISALLOW_COPY_AND_ASSIGN(SparseHistogram);
};

}  // namespace base

#endif  // BASE_METRICS_SPARSE_HISTOGRAM_H_
