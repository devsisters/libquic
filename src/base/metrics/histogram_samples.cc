// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/histogram_samples.h"

#include "base/compiler_specific.h"
#include "base/pickle.h"

namespace base {

namespace {

class SampleCountPickleIterator : public SampleCountIterator {
 public:
  explicit SampleCountPickleIterator(PickleIterator* iter);

  bool Done() const override;
  void Next() override;
  void Get(HistogramBase::Sample* min,
           HistogramBase::Sample* max,
           HistogramBase::Count* count) const override;

 private:
  PickleIterator* const iter_;

  HistogramBase::Sample min_;
  HistogramBase::Sample max_;
  HistogramBase::Count count_;
  bool is_done_;
};

SampleCountPickleIterator::SampleCountPickleIterator(PickleIterator* iter)
    : iter_(iter),
      is_done_(false) {
  Next();
}

bool SampleCountPickleIterator::Done() const {
  return is_done_;
}

void SampleCountPickleIterator::Next() {
  DCHECK(!Done());
  if (!iter_->ReadInt(&min_) ||
      !iter_->ReadInt(&max_) ||
      !iter_->ReadInt(&count_))
    is_done_ = true;
}

void SampleCountPickleIterator::Get(HistogramBase::Sample* min,
                                    HistogramBase::Sample* max,
                                    HistogramBase::Count* count) const {
  DCHECK(!Done());
  *min = min_;
  *max = max_;
  *count = count_;
}

}  // namespace

// Don't try to delegate behavior to the constructor below that accepts a
// Matadata pointer by passing &local_meta_. Such cannot be reliably passed
// because it has not yet been constructed -- no member variables have; the
// class itself is in the middle of being constructed. Using it to
// initialize meta_ is okay because the object now exists and local_meta_
// is before meta_ in the construction order.
HistogramSamples::HistogramSamples(uint64_t id)
    : meta_(&local_meta_) {
  meta_->id = id;
}

HistogramSamples::HistogramSamples(uint64_t id, Metadata* meta)
    : meta_(meta) {
  DCHECK(meta_->id == 0 || meta_->id == id);

  // It's possible that |meta| is contained in initialized, read-only memory
  // so it's essential that no write be done in that case.
  if (!meta_->id)
    meta_->id = id;
}

HistogramSamples::~HistogramSamples() {}

void HistogramSamples::Add(const HistogramSamples& other) {
  IncreaseSum(other.sum());
  subtle::NoBarrier_AtomicIncrement(&meta_->redundant_count,
                                    other.redundant_count());
  bool success = AddSubtractImpl(other.Iterator().get(), ADD);
  DCHECK(success);
}

bool HistogramSamples::AddFromPickle(PickleIterator* iter) {
  int64_t sum;
  HistogramBase::Count redundant_count;

  if (!iter->ReadInt64(&sum) || !iter->ReadInt(&redundant_count))
    return false;

  IncreaseSum(sum);
  subtle::NoBarrier_AtomicIncrement(&meta_->redundant_count,
                                    redundant_count);

  SampleCountPickleIterator pickle_iter(iter);
  return AddSubtractImpl(&pickle_iter, ADD);
}

void HistogramSamples::Subtract(const HistogramSamples& other) {
  IncreaseSum(-other.sum());
  subtle::NoBarrier_AtomicIncrement(&meta_->redundant_count,
                                    -other.redundant_count());
  bool success = AddSubtractImpl(other.Iterator().get(), SUBTRACT);
  DCHECK(success);
}

bool HistogramSamples::Serialize(Pickle* pickle) const {
  if (!pickle->WriteInt64(sum()))
    return false;
  if (!pickle->WriteInt(redundant_count()))
    return false;

  HistogramBase::Sample min;
  HistogramBase::Sample max;
  HistogramBase::Count count;
  for (std::unique_ptr<SampleCountIterator> it = Iterator(); !it->Done();
       it->Next()) {
    it->Get(&min, &max, &count);
    if (!pickle->WriteInt(min) ||
        !pickle->WriteInt(max) ||
        !pickle->WriteInt(count))
      return false;
  }
  return true;
}

void HistogramSamples::IncreaseSum(int64_t diff) {
#ifdef ARCH_CPU_64_BITS
  subtle::NoBarrier_AtomicIncrement(&meta_->sum, diff);
#else
  meta_->sum += diff;
#endif
}

void HistogramSamples::IncreaseRedundantCount(HistogramBase::Count diff) {
  subtle::NoBarrier_AtomicIncrement(&meta_->redundant_count, diff);
}

SampleCountIterator::~SampleCountIterator() {}

bool SampleCountIterator::GetBucketIndex(size_t* index) const {
  DCHECK(!Done());
  return false;
}

}  // namespace base
