// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_WRITE_BLOCKED_LIST_H_
#define NET_SPDY_WRITE_BLOCKED_LIST_H_

#include <algorithm>
#include <deque>

#include "base/containers/hash_tables.h"
#include "base/logging.h"
#include "net/spdy/spdy_protocol.h"

namespace net {

namespace test {
class WriteBlockedListPeer;
}  // namespace test

const int kHighestPriority = 0;
const int kLowestPriority = 7;

template <typename IdType>
class WriteBlockedList {
 public:
  // 0(1) size lookup.  0(1) insert at front or back.
  typedef std::deque<IdType> BlockedList;
  typedef typename BlockedList::iterator iterator;

  WriteBlockedList() {}

  static SpdyPriority ClampPriority(SpdyPriority priority) {
    if (priority < kHighestPriority) {
      LOG(DFATAL) << "Invalid priority: " << static_cast<int>(priority);
      return kHighestPriority;
    }
    if (priority > kLowestPriority) {
      LOG(DFATAL) << "Invalid priority: " << static_cast<int>(priority);
      return kLowestPriority;
    }
    return priority;
  }

  // Returns the priority of the highest priority list with sessions on it.
  SpdyPriority GetHighestPriorityWriteBlockedList() const {
    for (SpdyPriority i = 0; i <= kLowestPriority; ++i) {
      if (write_blocked_lists_[i].size() > 0) {
        return i;
      }
    }
    LOG(DFATAL) << "No blocked streams";
    return kHighestPriority;
  }

  IdType PopFront(SpdyPriority priority) {
    priority = ClampPriority(priority);
    DCHECK(!write_blocked_lists_[priority].empty());
    IdType stream_id = write_blocked_lists_[priority].front();
    write_blocked_lists_[priority].pop_front();
    stream_to_priority_.erase(stream_id);
    return stream_id;
  }

  bool HasWriteBlockedStreamsGreaterThanPriority(SpdyPriority priority) const {
    priority = ClampPriority(priority);
    for (SpdyPriority i = kHighestPriority; i < priority; ++i) {
      if (!write_blocked_lists_[i].empty()) {
        return true;
      }
    }
    return false;
  }

  bool HasWriteBlockedStreams() const {
    for (SpdyPriority i = kHighestPriority; i <= kLowestPriority; ++i) {
      if (!write_blocked_lists_[i].empty()) {
        return true;
      }
    }
    return false;
  }

  void PushBack(IdType stream_id, SpdyPriority priority) {
    priority = ClampPriority(priority);
    DVLOG(2) << "Adding stream " << stream_id << " at priority "
             << static_cast<int>(priority);
    bool should_insert_stream = true;
    typename StreamToPriorityMap::iterator iter =
        stream_to_priority_.find(stream_id);
    if (iter != stream_to_priority_.end()) {
      DVLOG(1) << "Stream " << stream_id << " already in write blocked list.";
      if (iter->second == priority) {
        // The stream is already in the write blocked list for the priority.
        should_insert_stream = false;
      } else {
        // The stream is in a write blocked list for a different priority.
        bool removed =
            RemoveStreamFromWriteBlockedList(stream_id, iter->second);
        DCHECK(removed);
      }
    }
    if (should_insert_stream) {
      stream_to_priority_[stream_id] = priority;
      write_blocked_lists_[priority].push_back(stream_id);
    }
  }

  bool RemoveStreamFromWriteBlockedList(IdType stream_id,
                                        SpdyPriority priority) {
    typename StreamToPriorityMap::iterator iter =
        stream_to_priority_.find(stream_id);
    if (iter == stream_to_priority_.end()) {
      // The stream is not present in the write blocked list.
      return false;
    } else if (iter->second == priority) {
      stream_to_priority_.erase(iter);
    } else {
      // The stream is not present at the specified priority level.
      return false;
    }
    // We shouldn't really add a stream_id to a list multiple times,
    // but under some conditions it does happen. Doing a check in PushBack
    // would be too costly, so instead we check here to eliminate duplicates.
    bool found = false;
    iterator it = std::find(write_blocked_lists_[priority].begin(),
                            write_blocked_lists_[priority].end(), stream_id);
    while (it != write_blocked_lists_[priority].end()) {
      found = true;
      iterator next_it = write_blocked_lists_[priority].erase(it);
      it = std::find(next_it, write_blocked_lists_[priority].end(), stream_id);
    }
    return found;
  }

  void UpdateStreamPriorityInWriteBlockedList(IdType stream_id,
                                              SpdyPriority old_priority,
                                              SpdyPriority new_priority) {
    if (old_priority == new_priority) {
      return;
    }
    bool found = RemoveStreamFromWriteBlockedList(stream_id, old_priority);
    if (found) {
      PushBack(stream_id, new_priority);
    }
  }

  size_t NumBlockedStreams() const {
    size_t num_blocked_streams = 0;
    for (SpdyPriority i = kHighestPriority; i <= kLowestPriority; ++i) {
      num_blocked_streams += write_blocked_lists_[i].size();
    }
    return num_blocked_streams;
  }

 private:
  friend class net::test::WriteBlockedListPeer;

  typedef base::hash_map<IdType, SpdyPriority> StreamToPriorityMap;

  BlockedList write_blocked_lists_[kLowestPriority + 1];
  StreamToPriorityMap stream_to_priority_;
};

}  // namespace net

#endif  // NET_SPDY_WRITE_BLOCKED_LIST_H_
