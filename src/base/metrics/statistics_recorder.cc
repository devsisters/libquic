// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/metrics/statistics_recorder.h"

#include <memory>

#include "base/at_exit.h"
#include "base/debug/leak_annotations.h"
#include "base/json/string_escape.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram.h"
#include "base/metrics/metrics_hashes.h"
#include "base/metrics/persistent_histogram_allocator.h"
#include "base/stl_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/lock.h"
#include "base/values.h"

namespace {

// Initialize histogram statistics gathering system.
base::LazyInstance<base::StatisticsRecorder>::Leaky g_statistics_recorder_ =
    LAZY_INSTANCE_INITIALIZER;

bool HistogramNameLesser(const base::HistogramBase* a,
                         const base::HistogramBase* b) {
  return a->histogram_name() < b->histogram_name();
}

}  // namespace

namespace base {

StatisticsRecorder::HistogramIterator::HistogramIterator(
    const HistogramMap::iterator& iter, bool include_persistent)
    : iter_(iter),
      include_persistent_(include_persistent) {
  // The starting location could point to a persistent histogram when such
  // is not wanted. If so, skip it.
  if (!include_persistent_ && iter_ != histograms_->end() &&
      (iter_->second->flags() & HistogramBase::kIsPersistent)) {
    // This operator will continue to skip until a non-persistent histogram
    // is found.
    operator++();
  }
}

StatisticsRecorder::HistogramIterator::HistogramIterator(
    const HistogramIterator& rhs)
    : iter_(rhs.iter_),
      include_persistent_(rhs.include_persistent_) {
}

StatisticsRecorder::HistogramIterator::~HistogramIterator() {}

StatisticsRecorder::HistogramIterator&
StatisticsRecorder::HistogramIterator::operator++() {
  const HistogramMap::iterator histograms_end = histograms_->end();
  if (iter_ == histograms_end || lock_ == NULL)
    return *this;

  base::AutoLock auto_lock(*lock_);

  for (;;) {
    ++iter_;
    if (iter_ == histograms_end)
      break;
    if (!include_persistent_ && (iter_->second->flags() &
                                 HistogramBase::kIsPersistent)) {
      continue;
    }
    break;
  }

  return *this;
}

StatisticsRecorder::~StatisticsRecorder() {
  DCHECK(lock_);
  DCHECK(histograms_);
  DCHECK(ranges_);

  // Clean out what this object created and then restore what existed before.
  Reset();
  base::AutoLock auto_lock(*lock_);
  histograms_ = existing_histograms_.release();
  callbacks_ = existing_callbacks_.release();
  ranges_ = existing_ranges_.release();
}

// static
void StatisticsRecorder::Initialize() {
  // Ensure that an instance of the StatisticsRecorder object is created.
  g_statistics_recorder_.Get();
}

// static
bool StatisticsRecorder::IsActive() {
  if (lock_ == NULL)
    return false;
  base::AutoLock auto_lock(*lock_);
  return NULL != histograms_;
}

// static
HistogramBase* StatisticsRecorder::RegisterOrDeleteDuplicate(
    HistogramBase* histogram) {
  // As per crbug.com/79322 the histograms are intentionally leaked, so we need
  // to annotate them. Because ANNOTATE_LEAKING_OBJECT_PTR may be used only once
  // for an object, the duplicates should not be annotated.
  // Callers are responsible for not calling RegisterOrDeleteDuplicate(ptr)
  // twice if (lock_ == NULL) || (!histograms_).
  if (lock_ == NULL) {
    ANNOTATE_LEAKING_OBJECT_PTR(histogram);  // see crbug.com/79322
    return histogram;
  }

  HistogramBase* histogram_to_delete = NULL;
  HistogramBase* histogram_to_return = NULL;
  {
    base::AutoLock auto_lock(*lock_);
    if (histograms_ == NULL) {
      histogram_to_return = histogram;
    } else {
      const std::string& name = histogram->histogram_name();
      HistogramMap::iterator it = histograms_->find(name);
      if (histograms_->end() == it) {
        // The StringKey references the name within |histogram| rather than
        // making a copy.
        (*histograms_)[name] = histogram;
        ANNOTATE_LEAKING_OBJECT_PTR(histogram);  // see crbug.com/79322
        // If there are callbacks for this histogram, we set the kCallbackExists
        // flag.
        auto callback_iterator = callbacks_->find(name);
        if (callback_iterator != callbacks_->end()) {
          if (!callback_iterator->second.is_null())
            histogram->SetFlags(HistogramBase::kCallbackExists);
          else
            histogram->ClearFlags(HistogramBase::kCallbackExists);
        }
        histogram_to_return = histogram;
      } else if (histogram == it->second) {
        // The histogram was registered before.
        histogram_to_return = histogram;
      } else {
        // We already have one histogram with this name.
        DCHECK_EQ(histogram->histogram_name(),
                  it->second->histogram_name()) << "hash collision";
        histogram_to_return = it->second;
        histogram_to_delete = histogram;
      }
    }
  }
  delete histogram_to_delete;
  return histogram_to_return;
}

// static
const BucketRanges* StatisticsRecorder::RegisterOrDeleteDuplicateRanges(
    const BucketRanges* ranges) {
  DCHECK(ranges->HasValidChecksum());
  std::unique_ptr<const BucketRanges> ranges_deleter;

  if (lock_ == NULL) {
    ANNOTATE_LEAKING_OBJECT_PTR(ranges);
    return ranges;
  }

  base::AutoLock auto_lock(*lock_);
  if (ranges_ == NULL) {
    ANNOTATE_LEAKING_OBJECT_PTR(ranges);
    return ranges;
  }

  std::list<const BucketRanges*>* checksum_matching_list;
  RangesMap::iterator ranges_it = ranges_->find(ranges->checksum());
  if (ranges_->end() == ranges_it) {
    // Add a new matching list to map.
    checksum_matching_list = new std::list<const BucketRanges*>();
    ANNOTATE_LEAKING_OBJECT_PTR(checksum_matching_list);
    (*ranges_)[ranges->checksum()] = checksum_matching_list;
  } else {
    checksum_matching_list = ranges_it->second;
  }

  for (const BucketRanges* existing_ranges : *checksum_matching_list) {
    if (existing_ranges->Equals(ranges)) {
      if (existing_ranges == ranges) {
        return ranges;
      } else {
        ranges_deleter.reset(ranges);
        return existing_ranges;
      }
    }
  }
  // We haven't found a BucketRanges which has the same ranges. Register the
  // new BucketRanges.
  checksum_matching_list->push_front(ranges);
  return ranges;
}

// static
void StatisticsRecorder::WriteHTMLGraph(const std::string& query,
                                        std::string* output) {
  if (!IsActive())
    return;

  Histograms snapshot;
  GetSnapshot(query, &snapshot);
  std::sort(snapshot.begin(), snapshot.end(), &HistogramNameLesser);
  for (const HistogramBase* histogram : snapshot) {
    histogram->WriteHTMLGraph(output);
    output->append("<br><hr><br>");
  }
}

// static
void StatisticsRecorder::WriteGraph(const std::string& query,
                                    std::string* output) {
  if (!IsActive())
    return;
  if (query.length())
    StringAppendF(output, "Collections of histograms for %s\n", query.c_str());
  else
    output->append("Collections of all histograms\n");

  Histograms snapshot;
  GetSnapshot(query, &snapshot);
  std::sort(snapshot.begin(), snapshot.end(), &HistogramNameLesser);
  for (const HistogramBase* histogram : snapshot) {
    histogram->WriteAscii(output);
    output->append("\n");
  }
}

// static
std::string StatisticsRecorder::ToJSON(const std::string& query) {
  if (!IsActive())
    return std::string();

  std::string output("{");
  if (!query.empty()) {
    output += "\"query\":";
    EscapeJSONString(query, true, &output);
    output += ",";
  }

  Histograms snapshot;
  GetSnapshot(query, &snapshot);
  output += "\"histograms\":[";
  bool first_histogram = true;
  for (const HistogramBase* histogram : snapshot) {
    if (first_histogram)
      first_histogram = false;
    else
      output += ",";
    std::string json;
    histogram->WriteJSON(&json);
    output += json;
  }
  output += "]}";
  return output;
}

// static
void StatisticsRecorder::GetHistograms(Histograms* output) {
  if (lock_ == NULL)
    return;
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return;

  for (const auto& entry : *histograms_) {
    output->push_back(entry.second);
  }
}

// static
void StatisticsRecorder::GetBucketRanges(
    std::vector<const BucketRanges*>* output) {
  if (lock_ == NULL)
    return;
  base::AutoLock auto_lock(*lock_);
  if (ranges_ == NULL)
    return;

  for (const auto& entry : *ranges_) {
    for (auto* range_entry : *entry.second) {
      output->push_back(range_entry);
    }
  }
}

// static
HistogramBase* StatisticsRecorder::FindHistogram(base::StringPiece name) {
  // This must be called *before* the lock is acquired below because it will
  // call back into this object to register histograms. Those called methods
  // will acquire the lock at that time.
  ImportGlobalPersistentHistograms();

  if (lock_ == NULL)
    return NULL;
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return NULL;

  HistogramMap::iterator it = histograms_->find(name);
  if (histograms_->end() == it)
    return NULL;
  return it->second;
}

// static
StatisticsRecorder::HistogramIterator StatisticsRecorder::begin(
    bool include_persistent) {
  DCHECK(histograms_);
  ImportGlobalPersistentHistograms();

  HistogramMap::iterator iter_begin;
  {
    base::AutoLock auto_lock(*lock_);
    iter_begin = histograms_->begin();
  }
  return HistogramIterator(iter_begin, include_persistent);
}

// static
StatisticsRecorder::HistogramIterator StatisticsRecorder::end() {
  HistogramMap::iterator iter_end;
  {
    base::AutoLock auto_lock(*lock_);
    iter_end = histograms_->end();
  }
  return HistogramIterator(iter_end, true);
}

// static
void StatisticsRecorder::GetSnapshot(const std::string& query,
                                     Histograms* snapshot) {
  if (lock_ == NULL)
    return;
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return;

  for (const auto& entry : *histograms_) {
    if (entry.second->histogram_name().find(query) != std::string::npos)
      snapshot->push_back(entry.second);
  }
}

// static
bool StatisticsRecorder::SetCallback(
    const std::string& name,
    const StatisticsRecorder::OnSampleCallback& cb) {
  DCHECK(!cb.is_null());
  if (lock_ == NULL)
    return false;
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return false;

  if (ContainsKey(*callbacks_, name))
    return false;
  callbacks_->insert(std::make_pair(name, cb));

  auto it = histograms_->find(name);
  if (it != histograms_->end())
    it->second->SetFlags(HistogramBase::kCallbackExists);

  return true;
}

// static
void StatisticsRecorder::ClearCallback(const std::string& name) {
  if (lock_ == NULL)
    return;
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return;

  callbacks_->erase(name);

  // We also clear the flag from the histogram (if it exists).
  auto it = histograms_->find(name);
  if (it != histograms_->end())
    it->second->ClearFlags(HistogramBase::kCallbackExists);
}

// static
StatisticsRecorder::OnSampleCallback StatisticsRecorder::FindCallback(
    const std::string& name) {
  if (lock_ == NULL)
    return OnSampleCallback();
  base::AutoLock auto_lock(*lock_);
  if (histograms_ == NULL)
    return OnSampleCallback();

  auto callback_iterator = callbacks_->find(name);
  return callback_iterator != callbacks_->end() ? callback_iterator->second
                                                : OnSampleCallback();
}

// static
size_t StatisticsRecorder::GetHistogramCount() {
  if (!lock_)
    return 0;

  base::AutoLock auto_lock(*lock_);
  if (!histograms_)
    return 0;
  return histograms_->size();
}

// static
void StatisticsRecorder::ForgetHistogramForTesting(base::StringPiece name) {
  if (histograms_)
    histograms_->erase(name);
}

// static
std::unique_ptr<StatisticsRecorder>
StatisticsRecorder::CreateTemporaryForTesting() {
  return WrapUnique(new StatisticsRecorder());
}

// static
void StatisticsRecorder::UninitializeForTesting() {
  // Stop now if it's never been initialized.
  if (lock_ == NULL || histograms_ == NULL)
    return;

  // Get the global instance and destruct it. It's held in static memory so
  // can't "delete" it; call the destructor explicitly.
  DCHECK(g_statistics_recorder_.private_instance_);
  g_statistics_recorder_.Get().~StatisticsRecorder();

  // Now the ugly part. There's no official way to release a LazyInstance once
  // created so it's necessary to clear out an internal variable which
  // shouldn't be publicly visible but is for initialization reasons.
  g_statistics_recorder_.private_instance_ = 0;
}

// static
void StatisticsRecorder::ImportGlobalPersistentHistograms() {
  if (lock_ == NULL)
    return;

  // Import histograms from known persistent storage. Histograms could have
  // been added by other processes and they must be fetched and recognized
  // locally. If the persistent memory segment is not shared between processes,
  // this call does nothing.
  GlobalHistogramAllocator* allocator = GlobalHistogramAllocator::Get();
  if (allocator)
    allocator->ImportHistogramsToStatisticsRecorder();
}

// This singleton instance should be started during the single threaded portion
// of main(), and hence it is not thread safe.  It initializes globals to
// provide support for all future calls.
StatisticsRecorder::StatisticsRecorder() {
  if (lock_ == NULL) {
    // This will leak on purpose. It's the only way to make sure we won't race
    // against the static uninitialization of the module while one of our
    // static methods relying on the lock get called at an inappropriate time
    // during the termination phase. Since it's a static data member, we will
    // leak one per process, which would be similar to the instance allocated
    // during static initialization and released only on  process termination.
    lock_ = new base::Lock;
  }

  base::AutoLock auto_lock(*lock_);

  existing_histograms_.reset(histograms_);
  existing_callbacks_.reset(callbacks_);
  existing_ranges_.reset(ranges_);

  histograms_ = new HistogramMap;
  callbacks_ = new CallbackMap;
  ranges_ = new RangesMap;

  if (VLOG_IS_ON(1))
    AtExitManager::RegisterCallback(&DumpHistogramsToVlog, this);
}

// static
void StatisticsRecorder::Reset() {
  // If there's no lock then there is nothing to reset.
  if (!lock_)
    return;

  std::unique_ptr<HistogramMap> histograms_deleter;
  std::unique_ptr<CallbackMap> callbacks_deleter;
  std::unique_ptr<RangesMap> ranges_deleter;
  // We don't delete lock_ on purpose to avoid having to properly protect
  // against it going away after we checked for NULL in the static methods.
  {
    base::AutoLock auto_lock(*lock_);
    histograms_deleter.reset(histograms_);
    callbacks_deleter.reset(callbacks_);
    ranges_deleter.reset(ranges_);
    histograms_ = NULL;
    callbacks_ = NULL;
    ranges_ = NULL;
  }
  // We are going to leak the histograms and the ranges.
}

// static
void StatisticsRecorder::DumpHistogramsToVlog(void* instance) {
  std::string output;
  StatisticsRecorder::WriteGraph(std::string(), &output);
  VLOG(1) << output;
}


// static
StatisticsRecorder::HistogramMap* StatisticsRecorder::histograms_ = NULL;
// static
StatisticsRecorder::CallbackMap* StatisticsRecorder::callbacks_ = NULL;
// static
StatisticsRecorder::RangesMap* StatisticsRecorder::ranges_ = NULL;
// static
base::Lock* StatisticsRecorder::lock_ = NULL;

}  // namespace base
