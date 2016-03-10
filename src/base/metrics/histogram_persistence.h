// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BASE_METRICS_HISTOGRAM_PERSISTENCE_H_
#define BASE_METRICS_HISTOGRAM_PERSISTENCE_H_

#include "base/base_export.h"
#include "base/feature_list.h"
#include "base/memory/scoped_ptr.h"
#include "base/metrics/histogram_base.h"
#include "base/metrics/persistent_memory_allocator.h"

namespace base {

// Feature definition for enabling histogram persistence.
BASE_EXPORT extern const Feature kPersistentHistogramsFeature;

// Histogram containing creation results. Visible for testing.
BASE_EXPORT HistogramBase* GetCreateHistogramResultHistogram();

// Access a PersistentMemoryAllocator for storing histograms in space that
// can be persisted or shared between processes. There is only ever one
// allocator for all such histograms created by a single process though one
// process may access the histograms created by other processes if it has a
// handle on its memory segment. This takes ownership of the object and
// should not be changed without great care as it is likely that there will
// be pointers to data held in that space. It should be called as soon as
// possible during startup to capture as many histograms as possible and
// while operating single-threaded so there are no race-conditions.
BASE_EXPORT void SetPersistentHistogramMemoryAllocator(
    PersistentMemoryAllocator* allocator);
BASE_EXPORT PersistentMemoryAllocator* GetPersistentHistogramMemoryAllocator();

// This access to the persistent allocator is only for testing; it extracts
// the current allocator completely. This allows easy creation of histograms
// within persistent memory segments which can then be extracted and used
// in other ways.
BASE_EXPORT PersistentMemoryAllocator*
ReleasePersistentHistogramMemoryAllocatorForTesting();

// Recreate a Histogram from data held in persistent memory. Though this
// object will be local to the current process, the sample data will be
// shared with all other threads referencing it. This method takes a |ref|
// to the top- level histogram data and the |allocator| on which it is found.
// This method will return nullptr if any problem is detected with the data.
// The |allocator| may or may not be the same as the PersistentMemoryAllocator
// set for general use so that this method can be used to extract Histograms
// from persistent memory segments other than the default place that this
// process is creating its own histograms. The caller must take ownership of
// the returned object and destroy it when no longer needed.
BASE_EXPORT HistogramBase* GetPersistentHistogram(
    PersistentMemoryAllocator* allocator,
    int32_t ref);

// Get the next histogram in persistent data based on iterator. The caller
// must take ownership of the returned object and destroy it when no longer
// needed.
BASE_EXPORT HistogramBase* GetNextPersistentHistogram(
    PersistentMemoryAllocator* allocator,
    PersistentMemoryAllocator::Iterator* iter);

// Finalize the creation of the histogram, making it available to other
// processes if it is the registered instance.
void FinalizePersistentHistogram(PersistentMemoryAllocator::Reference ref,
                                 bool register);

// Allocate a new persistent histogram. This does *not* make the object
// iterable in the allocator; call MakeIterable(ref) directly if that is
// desired.
BASE_EXPORT HistogramBase* AllocatePersistentHistogram(
    PersistentMemoryAllocator* allocator,
    HistogramType histogram_type,
    const std::string& name,
    int minimum,
    int maximum,
    const BucketRanges* bucket_ranges,
    int32_t flags,
    PersistentMemoryAllocator::Reference* ref_ptr);

// Import new histograms from attached PersistentMemoryAllocator. It's
// possible for other processes to create histograms in the attached memory
// segment; this adds those to the internal list of known histograms to
// avoid creating duplicates that would have to merged during reporting.
// Every call to this method resumes from the last entry it saw so it costs
// nothing if nothing new has been added.
void ImportPersistentHistograms();

}  // namespace base

#endif  // BASE_METRICS_HISTOGRAM_PERSISTENCE_H_
