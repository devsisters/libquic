// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_frame_list.h"

#include "base/logging.h"

namespace net {

QuicFrameList::FrameData::FrameData(QuicStreamOffset offset,
                                    string segment,
                                    const QuicTime timestamp)
    : offset(offset), segment(segment), timestamp(timestamp) {}

QuicFrameList::QuicFrameList() {}

QuicFrameList::~QuicFrameList() {
  Clear();
}

void QuicFrameList::Clear() {
  frame_list_.clear();
  num_bytes_buffered_ = 0;
}

bool QuicFrameList::Empty() const {
  return frame_list_.empty();
}

QuicErrorCode QuicFrameList::OnStreamData(QuicStreamOffset offset,
                                          StringPiece data,
                                          QuicTime timestamp,
                                          size_t* const bytes_buffered) {
  *bytes_buffered = 0;
  const size_t data_len = data.size();
  auto insertion_point = FindInsertionPoint(offset, data_len);
  if (IsDuplicate(offset, data_len, insertion_point)) {
    return QUIC_NO_ERROR;
  }

  if (FrameOverlapsBufferedData(offset, data_len, insertion_point)) {
    return QUIC_INVALID_STREAM_DATA;
  }

  DVLOG(1) << "Buffering stream data at offset " << offset;
  // Inserting an empty string and then copying to avoid the extra copy.
  insertion_point =
      frame_list_.insert(insertion_point, FrameData(offset, "", timestamp));
  data.CopyToString(&insertion_point->segment);
  *bytes_buffered = data_len;
  num_bytes_buffered_ += data_len;
  return QUIC_NO_ERROR;
}

// Finds the place the frame should be inserted.  If an identical frame is
// present, stops on the identical frame.
list<QuicFrameList::FrameData>::iterator QuicFrameList::FindInsertionPoint(
    QuicStreamOffset offset,
    size_t len) {
  if (frame_list_.empty()) {
    return frame_list_.begin();
  }
  // If it's after all buffered_frames, return the end.
  if (offset >=
      (frame_list_.rbegin()->offset + frame_list_.rbegin()->segment.length())) {
    return frame_list_.end();
  }
  auto iter = frame_list_.begin();
  // Only advance the iterator if the data begins after the already received
  // frame.  If the new frame overlaps with an existing frame, the iterator will
  // still point to the frame it overlaps with.
  while (iter != frame_list_.end() &&
         offset >= iter->offset + iter->segment.length()) {
    ++iter;
  }
  return iter;
}

// Returns true if |frame| contains data which overlaps buffered data
// (indicating an invalid stream frame has been received).
bool QuicFrameList::FrameOverlapsBufferedData(
    QuicStreamOffset offset,
    size_t data_len,
    list<FrameData>::const_iterator insertion_point) const {
  if (frame_list_.empty() || insertion_point == frame_list_.end()) {
    return false;
  }
  // If there is a buffered frame with a higher starting offset, then check to
  // see if the new frame overlaps the beginning of the higher frame.
  if (offset < insertion_point->offset &&
      offset + data_len > insertion_point->offset) {
    DVLOG(1) << "New frame overlaps next frame: " << offset << " + " << data_len
             << " > " << insertion_point->offset;
    return true;
  }
  // If there is a buffered frame with a lower starting offset, then check to
  // see if the buffered frame runs into the new frame.
  if (offset >= insertion_point->offset &&
      offset < insertion_point->offset + insertion_point->segment.length()) {
    DVLOG(1) << "Preceeding frame overlaps new frame: "
             << insertion_point->offset << " + "
             << insertion_point->segment.length() << " > " << offset;
    return true;
  }

  return false;
}

// Returns true if the sequencer has received this frame before.
bool QuicFrameList::IsDuplicate(
    QuicStreamOffset offset,
    size_t data_len,
    list<FrameData>::const_iterator insertion_point) const {
  // A frame is duplicate if the frame offset is smaller than the bytes consumed
  // or identical to an already received frame.
  return offset < total_bytes_read_ || (insertion_point != frame_list_.end() &&
                                        offset == insertion_point->offset);
}

int QuicFrameList::GetReadableRegions(struct iovec* iov, int iov_len) const {
  list<FrameData>::const_iterator it = frame_list_.begin();
  int index = 0;
  QuicStreamOffset offset = total_bytes_read_;
  while (it != frame_list_.end() && index < iov_len) {
    if (it->offset != offset) {
      return index;
    }

    iov[index].iov_base =
        static_cast<void*>(const_cast<char*>(it->segment.data()));
    iov[index].iov_len = it->segment.size();
    offset += it->segment.size();

    ++index;
    ++it;
  }
  return index;
}

bool QuicFrameList::GetReadableRegion(iovec* iov, QuicTime* timestamp) const {
  list<FrameData>::const_iterator it = frame_list_.begin();
  if (it == frame_list_.end() || it->offset != total_bytes_read_) {
    return false;
  }
  iov->iov_base = static_cast<void*>(const_cast<char*>(it->segment.data()));
  iov->iov_len = it->segment.size();
  *timestamp = it->timestamp;
  return true;
}

bool QuicFrameList::MarkConsumed(size_t bytes_used) {
  size_t end_offset = total_bytes_read_ + bytes_used;
  while (!frame_list_.empty() && end_offset != total_bytes_read_) {
    list<FrameData>::iterator it = frame_list_.begin();
    if (it->offset != total_bytes_read_) {
      return false;
    }

    if (it->offset + it->segment.length() <= end_offset) {
      total_bytes_read_ += it->segment.length();
      num_bytes_buffered_ -= it->segment.length();
      // This chunk is entirely consumed.
      frame_list_.erase(it);
      continue;
    }

    // Partially consume this frame.
    size_t delta = end_offset - it->offset;
    total_bytes_read_ += delta;
    num_bytes_buffered_ -= delta;
    string new_data = it->segment.substr(delta);
    const QuicTime timestamp = it->timestamp;
    frame_list_.erase(it);
    frame_list_.push_front(FrameData(total_bytes_read_, new_data, timestamp));
    break;
  }
  return true;
}

size_t QuicFrameList::Readv(const struct iovec* iov, size_t iov_len) {
  list<FrameData>::iterator it = frame_list_.begin();
  size_t iov_index = 0;
  size_t iov_offset = 0;
  size_t frame_offset = 0;
  QuicStreamOffset initial_bytes_consumed = total_bytes_read_;

  while (iov_index < iov_len && it != frame_list_.end() &&
         it->offset == total_bytes_read_) {
    int bytes_to_read = std::min(iov[iov_index].iov_len - iov_offset,
                                 it->segment.size() - frame_offset);

    char* iov_ptr = static_cast<char*>(iov[iov_index].iov_base) + iov_offset;
    memcpy(iov_ptr, it->segment.data() + frame_offset, bytes_to_read);
    frame_offset += bytes_to_read;
    iov_offset += bytes_to_read;

    if (iov[iov_index].iov_len == iov_offset) {
      // We've filled this buffer.
      iov_offset = 0;
      ++iov_index;
    }
    if (it->segment.size() == frame_offset) {
      // We've copied this whole frame
      total_bytes_read_ += it->segment.size();
      num_bytes_buffered_ -= it->segment.size();
      frame_list_.erase(it);
      it = frame_list_.begin();
      frame_offset = 0;
    }
  }
  // Done copying.  If there is a partial frame, update it.
  if (frame_offset != 0) {
    frame_list_.push_front(FrameData(it->offset + frame_offset,
                                     it->segment.substr(frame_offset),
                                     it->timestamp));
    frame_list_.erase(it);
    total_bytes_read_ += frame_offset;
    num_bytes_buffered_ -= frame_offset;
  }
  return total_bytes_read_ - initial_bytes_consumed;
}

size_t QuicFrameList::FlushBufferedFrames() {
  QuicStreamOffset initial_bytes_consumed = total_bytes_read_;
  if (!frame_list_.empty()) {
    // Consume all of the bytes up to the last byte yet seen, including the
    // ones that haven't arrived yet.
    auto it = frame_list_.back();
    total_bytes_read_ = it.offset + it.segment.length();
    frame_list_.clear();
  }
  return total_bytes_read_ - initial_bytes_consumed;
}

bool QuicFrameList::HasBytesToRead() const {
  return !frame_list_.empty() &&
         frame_list_.begin()->offset == total_bytes_read_;
}

QuicStreamOffset QuicFrameList::BytesConsumed() const {
  return total_bytes_read_;
}

size_t QuicFrameList::BytesBuffered() const {
  return num_bytes_buffered_;
}

}  // namespace net_quic
