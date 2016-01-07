// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_
#define NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_

#include <stddef.h>

#include <algorithm>
#include <deque>
#include <unordered_map>
#include <utility>

#include "base/logging.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

// Class that manages the order in which streams are written using the SPDY
// priority scheme described at:
// https://www.chromium.org/spdy/spdy-protocol/spdy-protocol-draft3-1#TOC-2.3.3-Stream-priority
//
// Callers must first register a stream with the PriorityWriteScheduler (by
// calling RegisterStream(), which informs the PriorityWriteScheduler of the
// stream's priority) before calling other methods referencing that stream,
// which may implicitly use the stream's priority. When the stream is
// eventually closed, the caller should unregister it from the
// PriorityWriteScheduler (by calling UnregisterStream()), to free data
// structures associated with it.
//
// Each stream can be in one of two states: ready or not ready (for writing).
// Ready state is changed by calling the MarkStreamReady() and
// MarkStreamNotReady() methods. Only streams in the ready state can be
// returned by PopNextReadyStream(); when returned by that method, the stream's
// state changes to not ready.
//
// Internally, PriorityWriteScheduler consists of 8 per-priority sublists, one
// for each priority value.  The elements (if any) of each sublist are streams
// that are ready to write and have that priority.
template <typename StreamIdType>
class PriorityWriteScheduler {
 public:
  // Creates scheduler with no streams.
  PriorityWriteScheduler() = default;

  // Registers the given stream with the scheduler, which will now track its
  // priority and ready state. If the stream was already registered, logs
  // DFATAL and does nothing.
  void RegisterStream(StreamIdType stream_id, SpdyPriority priority) {
    priority = ClampPriority(priority);
    StreamInfo stream_info = {priority, false};
    bool inserted =
        stream_infos_.insert(std::make_pair(stream_id, stream_info)).second;
    if (!inserted) {
      LOG(DFATAL) << "Stream " << stream_id << " already registered";
    }
  }

  // Unregisters the given stream from the scheduler, which will no
  // longer keep track of its priority and ready state. If the stream
  // was not previously registered, logs DFATAL and does nothing.
  void UnregisterStream(StreamIdType stream_id) {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.ready) {
      bool erased = Erase(&ready_lists_[stream_info.priority], stream_id);
      DCHECK(erased);
    }
    stream_infos_.erase(it);
  }

  // Returns the priority value for the specified stream. If the stream is not
  // registered, logs DFATAL and returns the lowest priority.
  SpdyPriority GetStreamPriority(StreamIdType stream_id) const {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return kV3LowestPriority;
    }
    return it->second.priority;
  }

  // Updates the priority of the given stream. If the stream is not registered,
  // logs DFATAL and does nothing.
  void UpdateStreamPriority(StreamIdType stream_id, SpdyPriority priority) {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.priority == priority) {
      return;
    }
    if (stream_info.ready) {
      bool erased = Erase(&ready_lists_[stream_info.priority], stream_id);
      DCHECK(erased);
      ready_lists_[priority].push_back(stream_id);
    }
    stream_info.priority = priority;
  }

  // If the scheduler has any ready streams, pops the next stream ID from the
  // highest priority non-empty ready list and returns it, transitioning the
  // stream from ready to not ready. If the scheduler doesn't have any ready
  // streams, logs DFATAL and returns 0.
  StreamIdType PopNextReadyStream() {
    StreamIdType stream_id = 0;
    for (SpdyPriority p = kV3HighestPriority; p <= kV3LowestPriority; ++p) {
      StreamIdList& ready_list = ready_lists_[p];
      if (!ready_list.empty()) {
        stream_id = ready_list.front();
        ready_list.pop_front();

        auto it = stream_infos_.find(stream_id);
        if (it == stream_infos_.end()) {
          LOG(DFATAL) << "Missing StreamInfo for stream " << stream_id;
        } else {
          it->second.ready = false;
        }
        return stream_id;
      }
    }
    LOG(DFATAL) << "No ready streams available";
    return stream_id;
  }

  // Returns true if the scheduler has any ready streams with a higher priority
  // than that of the specified stream. If the stream is not registered, logs
  // DFATAL and returns false.
  bool HasHigherPriorityReadyStream(StreamIdType stream_id) {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return false;
    }
    StreamInfo& stream_info = it->second;
    for (SpdyPriority p = kV3HighestPriority; p < stream_info.priority; ++p) {
      if (!ready_lists_[p].empty()) {
        return true;
      }
    }
    return false;
  }

  // Marks the given stream as ready to write. If stream was already ready,
  // does nothing. If stream was not registered, logs DFATAL and does
  // nothing. If |add_to_front| is true, adds stream to the front of its
  // per-priority ready list, otherwise adds it to the back.
  void MarkStreamReady(StreamIdType stream_id, bool add_to_front) {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (stream_info.ready) {
      return;
    }
    StreamIdList& ready_list = ready_lists_[stream_info.priority];
    if (add_to_front) {
      ready_list.push_front(stream_id);
    } else {
      ready_list.push_back(stream_id);
    }
    stream_info.ready = true;
  }

  // Marks the given stream as not ready to write, removing it from the ready
  // list for its priority. If stream was already not ready, does nothing. If
  // stream was not registered, logs DFATAL and does nothing.
  void MarkStreamNotReady(StreamIdType stream_id) {
    auto it = stream_infos_.find(stream_id);
    if (it == stream_infos_.end()) {
      LOG(DFATAL) << "Stream " << stream_id << " not registered";
      return;
    }
    StreamInfo& stream_info = it->second;
    if (!stream_info.ready) {
      return;
    }
    bool erased = Erase(&ready_lists_[stream_info.priority], stream_id);
    DCHECK(erased);
    stream_info.ready = false;
  }

  // Returns true iff the number of ready streams is non-zero.
  bool HasReadyStreams() const {
    for (SpdyPriority i = kV3HighestPriority; i <= kV3LowestPriority; ++i) {
      if (!ready_lists_[i].empty()) {
        return true;
      }
    }
    return false;
  }

  // Returns the number of ready streams.
  size_t NumReadyStreams() const {
    size_t n = 0;
    for (SpdyPriority i = kV3HighestPriority; i <= kV3LowestPriority; ++i) {
      n += ready_lists_[i].size();
    }
    return n;
  }

  // Returns the number of ready streams with the given priority.
  size_t NumReadyStreams(SpdyPriority priority) const {
    priority = ClampPriority(priority);
    return ready_lists_[priority].size();
  }

 private:
  // 0(1) size lookup, 0(1) insert at front or back.
  typedef std::deque<StreamIdType> StreamIdList;

  // State kept for all registered streams. All ready streams have ready = true
  // and should be present in ready_lists_[priority].
  struct StreamInfo {
    SpdyPriority priority;
    bool ready;
  };

  typedef std::unordered_map<StreamIdType, StreamInfo> StreamInfoMap;

  static SpdyPriority ClampPriority(SpdyPriority priority) {
    if (priority < kV3HighestPriority) {
      LOG(DFATAL) << "Invalid priority: " << static_cast<int>(priority);
      return kV3HighestPriority;
    }
    if (priority > kV3LowestPriority) {
      LOG(DFATAL) << "Invalid priority: " << static_cast<int>(priority);
      return kV3LowestPriority;
    }
    return priority;
  }

  // Erases first occurrence (which should be the only one) of |stream_id| in
  // |ready_list|, returning true if found (and erased), or false otherwise.
  bool Erase(StreamIdList* ready_list, StreamIdType stream_id) {
    auto it = std::find(ready_list->begin(), ready_list->end(), stream_id);
    if (it == ready_list->end()) {
      return false;
    }
    ready_list->erase(it);
    return true;
  }

  // IDs of streams that are ready to write, grouped by priority.
  StreamIdList ready_lists_[kV3LowestPriority + 1];
  // StreamInfos for all registered streams.
  StreamInfoMap stream_infos_;
};

}  // namespace net

#endif  // NET_SPDY_PRIORITY_WRITE_SCHEDULER_H_
