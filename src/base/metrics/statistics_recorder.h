// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// StatisticsRecorder holds all Histograms and BucketRanges that are used by
// Histograms in the system. It provides a general place for
// Histograms/BucketRanges to register, and supports a global API for accessing
// (i.e., dumping, or graphing) the data.

#ifndef BASE_METRICS_STATISTICS_RECORDER_H_
#define BASE_METRICS_STATISTICS_RECORDER_H_

#include <stdint.h>

#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "base/base_export.h"
#include "base/callback.h"
#include "base/gtest_prod_util.h"
#include "base/lazy_instance.h"
#include "base/macros.h"
#include "base/metrics/histogram_base.h"
#include "base/strings/string_piece.h"

class SubprocessMetricsProviderTest;

namespace base {

class BucketRanges;
class Lock;

class BASE_EXPORT StatisticsRecorder {
 public:
  // A class used as a key for the histogram map below. It always references
  // a string owned outside of this class, likely in the value of the map.
  class StringKey : public StringPiece {
   public:
    // Constructs the StringKey using various sources. The source must live
    // at least as long as the created object.
    StringKey(const std::string& str) : StringPiece(str) {}
    StringKey(StringPiece str) : StringPiece(str) {}

    // Though StringPiece is better passed by value than by reference, in
    // this case it's being passed many times and likely already been stored
    // in memory (not just registers) so the benefit of pass-by-value is
    // negated.
    bool operator<(const StringKey& rhs) const {
      // Since order is unimportant in the map and string comparisons can be
      // slow, use the length as the primary sort value.
      if (length() < rhs.length())
        return true;
      if (length() > rhs.length())
        return false;

      // Fall back to an actual string comparison. The lengths are the same
      // so a simple memory-compare is sufficient. This is slightly more
      // efficient than calling operator<() for StringPiece which would
      // again have to check lengths before calling wordmemcmp().
      return wordmemcmp(data(), rhs.data(), length()) < 0;
    }
  };

  typedef std::map<StringKey, HistogramBase*> HistogramMap;
  typedef std::vector<HistogramBase*> Histograms;

  // A class for iterating over the histograms held within this global resource.
  class BASE_EXPORT HistogramIterator {
   public:
    HistogramIterator(const HistogramMap::iterator& iter,
                      bool include_persistent);
    HistogramIterator(const HistogramIterator& rhs);  // Must be copyable.
    ~HistogramIterator();

    HistogramIterator& operator++();
    HistogramIterator operator++(int) {
      HistogramIterator tmp(*this);
      operator++();
      return tmp;
    }

    bool operator==(const HistogramIterator& rhs) const {
      return iter_ == rhs.iter_;
    }
    bool operator!=(const HistogramIterator& rhs) const {
      return iter_ != rhs.iter_;
    }
    HistogramBase* operator*() { return iter_->second; }

   private:
    HistogramMap::iterator iter_;
    const bool include_persistent_;
  };

  ~StatisticsRecorder();

  // Initializes the StatisticsRecorder system. Safe to call multiple times.
  static void Initialize();

  // Find out if histograms can now be registered into our list.
  static bool IsActive();

  // Register, or add a new histogram to the collection of statistics. If an
  // identically named histogram is already registered, then the argument
  // |histogram| will deleted.  The returned value is always the registered
  // histogram (either the argument, or the pre-existing registered histogram).
  static HistogramBase* RegisterOrDeleteDuplicate(HistogramBase* histogram);

  // Register, or add a new BucketRanges. If an identically BucketRanges is
  // already registered, then the argument |ranges| will deleted. The returned
  // value is always the registered BucketRanges (either the argument, or the
  // pre-existing one).
  static const BucketRanges* RegisterOrDeleteDuplicateRanges(
      const BucketRanges* ranges);

  // Methods for appending histogram data to a string.  Only histograms which
  // have |query| as a substring are written to |output| (an empty string will
  // process all registered histograms).
  static void WriteHTMLGraph(const std::string& query, std::string* output);
  static void WriteGraph(const std::string& query, std::string* output);

  // Returns the histograms with |query| as a substring as JSON text (an empty
  // |query| will process all registered histograms).
  static std::string ToJSON(const std::string& query);

  // Method for extracting histograms which were marked for use by UMA.
  static void GetHistograms(Histograms* output);

  // Method for extracting BucketRanges used by all histograms registered.
  static void GetBucketRanges(std::vector<const BucketRanges*>* output);

  // Find a histogram by name. It matches the exact name. This method is thread
  // safe.  It returns NULL if a matching histogram is not found.
  static HistogramBase* FindHistogram(base::StringPiece name);

  // Support for iterating over known histograms.
  static HistogramIterator begin(bool include_persistent);
  static HistogramIterator end();

  // GetSnapshot copies some of the pointers to registered histograms into the
  // caller supplied vector (Histograms). Only histograms which have |query| as
  // a substring are copied (an empty string will process all registered
  // histograms).
  static void GetSnapshot(const std::string& query, Histograms* snapshot);

  typedef base::Callback<void(HistogramBase::Sample)> OnSampleCallback;

  // SetCallback sets the callback to notify when a new sample is recorded on
  // the histogram referred to by |histogram_name|. The call to this method can
  // be be done before or after the histogram is created. This method is thread
  // safe. The return value is whether or not the callback was successfully set.
  static bool SetCallback(const std::string& histogram_name,
                          const OnSampleCallback& callback);

  // ClearCallback clears any callback set on the histogram referred to by
  // |histogram_name|. This method is thread safe.
  static void ClearCallback(const std::string& histogram_name);

  // FindCallback retrieves the callback for the histogram referred to by
  // |histogram_name|, or a null callback if no callback exists for this
  // histogram. This method is thread safe.
  static OnSampleCallback FindCallback(const std::string& histogram_name);

  // Returns the number of known histograms.
  static size_t GetHistogramCount();

  // Removes a histogram from the internal set of known ones. This can be
  // necessary during testing persistent histograms where the underlying
  // memory is being released.
  static void ForgetHistogramForTesting(base::StringPiece name);

  // Creates a local StatisticsRecorder object for testing purposes. All new
  // histograms will be registered in it until it is destructed or pushed
  // aside for the lifetime of yet another SR object. The destruction of the
  // returned object will re-activate the previous one. Always release SR
  // objects in the opposite order to which they're created.
  static std::unique_ptr<StatisticsRecorder> CreateTemporaryForTesting()
      WARN_UNUSED_RESULT;

  // Resets any global instance of the statistics-recorder that was created
  // by a call to Initialize().
  static void UninitializeForTesting();

 private:
  // We keep a map of callbacks to histograms, so that as histograms are
  // created, we can set the callback properly.
  typedef std::map<std::string, OnSampleCallback> CallbackMap;

  // We keep all |bucket_ranges_| in a map, from checksum to a list of
  // |bucket_ranges_|.  Checksum is calculated from the |ranges_| in
  // |bucket_ranges_|.
  typedef std::map<uint32_t, std::list<const BucketRanges*>*> RangesMap;

  friend struct DefaultLazyInstanceTraits<StatisticsRecorder>;

  // Imports histograms from global persistent memory. The global lock must
  // not be held during this call.
  static void ImportGlobalPersistentHistograms();

  // The constructor just initializes static members. Usually client code should
  // use Initialize to do this. But in test code, you can friend this class and
  // call the constructor to get a clean StatisticsRecorder.
  StatisticsRecorder();

  // These are copies of everything that existed when the (test) Statistics-
  // Recorder was created. The global ones have to be moved aside to create a
  // clean environment.
  std::unique_ptr<HistogramMap> existing_histograms_;
  std::unique_ptr<CallbackMap> existing_callbacks_;
  std::unique_ptr<RangesMap> existing_ranges_;

  static void Reset();
  static void DumpHistogramsToVlog(void* instance);

  static HistogramMap* histograms_;
  static CallbackMap* callbacks_;
  static RangesMap* ranges_;

  // Lock protects access to above maps.
  static base::Lock* lock_;

  DISALLOW_COPY_AND_ASSIGN(StatisticsRecorder);
};

}  // namespace base

#endif  // BASE_METRICS_STATISTICS_RECORDER_H_
