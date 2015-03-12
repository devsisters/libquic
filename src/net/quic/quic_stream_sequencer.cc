// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_stream_sequencer.h"

#include <algorithm>
#include <limits>

#include "base/logging.h"
#include "base/metrics/sparse_histogram.h"
#include "net/quic/reliable_quic_stream.h"

using std::min;
using std::numeric_limits;
using std::string;

namespace net {

QuicStreamSequencer::QuicStreamSequencer(ReliableQuicStream* quic_stream)
    : stream_(quic_stream),
      num_bytes_consumed_(0),
      close_offset_(numeric_limits<QuicStreamOffset>::max()),
      blocked_(false),
      num_bytes_buffered_(0),
      num_frames_received_(0),
      num_duplicate_frames_received_(0),
      num_early_frames_received_(0) {
}

QuicStreamSequencer::~QuicStreamSequencer() {
}

void QuicStreamSequencer::OnStreamFrame(const QuicStreamFrame& frame) {
  ++num_frames_received_;
  if (IsDuplicate(frame)) {
    ++num_duplicate_frames_received_;
    // Silently ignore duplicates.
    return;
  }

  if (FrameOverlapsBufferedData(frame)) {
    stream_->CloseConnectionWithDetails(
        QUIC_INVALID_STREAM_FRAME, "Stream frame overlaps with buffered data.");
    return;
  }

  QuicStreamOffset byte_offset = frame.offset;
  size_t data_len = frame.data.TotalBufferSize();
  if (data_len == 0 && !frame.fin) {
    // Stream frames must have data or a fin flag.
    stream_->CloseConnectionWithDetails(QUIC_INVALID_STREAM_FRAME,
                                        "Empty stream frame without FIN set.");
    return;
  }

  if (frame.fin) {
    CloseStreamAtOffset(frame.offset + data_len);
    if (data_len == 0) {
      return;
    }
  }

  IOVector data;
  data.AppendIovec(frame.data.iovec(), frame.data.Size());

  if (byte_offset > num_bytes_consumed_) {
    ++num_early_frames_received_;
  }

  // If the frame has arrived in-order then we can process it immediately, only
  // buffering if the stream is unable to process it.
  if (!blocked_ && byte_offset == num_bytes_consumed_) {
    DVLOG(1) << "Processing byte offset " << byte_offset;
    size_t bytes_consumed = 0;
    for (size_t i = 0; i < data.Size(); ++i) {
      bytes_consumed += stream_->ProcessRawData(
          static_cast<char*>(data.iovec()[i].iov_base),
          data.iovec()[i].iov_len);
    }
    num_bytes_consumed_ += bytes_consumed;
    stream_->AddBytesConsumed(bytes_consumed);

    if (MaybeCloseStream()) {
      return;
    }
    if (bytes_consumed > data_len) {
      stream_->Reset(QUIC_ERROR_PROCESSING_STREAM);
      return;
    } else if (bytes_consumed == data_len) {
      FlushBufferedFrames();
      return;  // it's safe to ack this frame.
    } else {
      // Set ourselves up to buffer what's left.
      data_len -= bytes_consumed;
      data.Consume(bytes_consumed);
      byte_offset += bytes_consumed;
    }
  }

  // Buffer any remaining data to be consumed by the stream when ready.
  for (size_t i = 0; i < data.Size(); ++i) {
    DVLOG(1) << "Buffering stream data at offset " << byte_offset;
    const iovec& iov = data.iovec()[i];
    buffered_frames_.insert(std::make_pair(
        byte_offset, string(static_cast<char*>(iov.iov_base), iov.iov_len)));
    byte_offset += iov.iov_len;
    num_bytes_buffered_ += iov.iov_len;
  }
  return;
}

void QuicStreamSequencer::CloseStreamAtOffset(QuicStreamOffset offset) {
  const QuicStreamOffset kMaxOffset = numeric_limits<QuicStreamOffset>::max();

  // If we have a scheduled termination or close, any new offset should match
  // it.
  if (close_offset_ != kMaxOffset && offset != close_offset_) {
    stream_->Reset(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    return;
  }

  close_offset_ = offset;

  MaybeCloseStream();
}

bool QuicStreamSequencer::MaybeCloseStream() {
  if (!blocked_ && IsClosed()) {
    DVLOG(1) << "Passing up termination, as we've processed "
             << num_bytes_consumed_ << " of " << close_offset_
             << " bytes.";
    // Technically it's an error if num_bytes_consumed isn't exactly
    // equal, but error handling seems silly at this point.
    stream_->OnFinRead();
    buffered_frames_.clear();
    num_bytes_buffered_ = 0;
    return true;
  }
  return false;
}

int QuicStreamSequencer::GetReadableRegions(iovec* iov, size_t iov_len) {
  DCHECK(!blocked_);
  FrameMap::iterator it = buffered_frames_.begin();
  size_t index = 0;
  QuicStreamOffset offset = num_bytes_consumed_;
  while (it != buffered_frames_.end() && index < iov_len) {
    if (it->first != offset) return index;

    iov[index].iov_base = static_cast<void*>(
        const_cast<char*>(it->second.data()));
    iov[index].iov_len = it->second.size();
    offset += it->second.size();

    ++index;
    ++it;
  }
  return index;
}

int QuicStreamSequencer::Readv(const struct iovec* iov, size_t iov_len) {
  DCHECK(!blocked_);
  FrameMap::iterator it = buffered_frames_.begin();
  size_t iov_index = 0;
  size_t iov_offset = 0;
  size_t frame_offset = 0;
  QuicStreamOffset initial_bytes_consumed = num_bytes_consumed_;

  while (iov_index < iov_len &&
         it != buffered_frames_.end() &&
         it->first == num_bytes_consumed_) {
    int bytes_to_read = min(iov[iov_index].iov_len - iov_offset,
                            it->second.size() - frame_offset);

    char* iov_ptr = static_cast<char*>(iov[iov_index].iov_base) + iov_offset;
    memcpy(iov_ptr,
           it->second.data() + frame_offset, bytes_to_read);
    frame_offset += bytes_to_read;
    iov_offset += bytes_to_read;

    if (iov[iov_index].iov_len == iov_offset) {
      // We've filled this buffer.
      iov_offset = 0;
      ++iov_index;
    }
    if (it->second.size() == frame_offset) {
      // We've copied this whole frame
      RecordBytesConsumed(it->second.size());
      buffered_frames_.erase(it);
      it = buffered_frames_.begin();
      frame_offset = 0;
    }
  }
  // We've finished copying.  If we have a partial frame, update it.
  if (frame_offset != 0) {
    buffered_frames_.insert(std::make_pair(it->first + frame_offset,
                                           it->second.substr(frame_offset)));
    buffered_frames_.erase(buffered_frames_.begin());
    RecordBytesConsumed(frame_offset);
  }
  return static_cast<int>(num_bytes_consumed_ - initial_bytes_consumed);
}

bool QuicStreamSequencer::HasBytesToRead() const {
  FrameMap::const_iterator it = buffered_frames_.begin();

  return it != buffered_frames_.end() && it->first == num_bytes_consumed_;
}

bool QuicStreamSequencer::IsClosed() const {
  return num_bytes_consumed_ >= close_offset_;
}

bool QuicStreamSequencer::FrameOverlapsBufferedData(
    const QuicStreamFrame& frame) const {
  if (buffered_frames_.empty()) {
    return false;
  }

  FrameMap::const_iterator next_frame =
      buffered_frames_.lower_bound(frame.offset);
  // Duplicate frames should have been dropped in IsDuplicate.
  DCHECK(next_frame == buffered_frames_.end() ||
         next_frame->first != frame.offset);

  // If there is a buffered frame with a higher starting offset, then we check
  // to see if the new frame runs into the higher frame.
  if (next_frame != buffered_frames_.end() &&
      (frame.offset + frame.data.TotalBufferSize()) > next_frame->first) {
    DVLOG(1) << "New frame overlaps next frame: " << frame.offset << " + "
             << frame.data.TotalBufferSize() << " > " << next_frame->first;
    return true;
  }

  // If there is a buffered frame with a lower starting offset, then we check
  // to see if the buffered frame runs into the new frame.
  if (next_frame != buffered_frames_.begin()) {
    FrameMap::const_iterator preceeding_frame = --next_frame;
    QuicStreamOffset offset = preceeding_frame->first;
    uint64 data_length = preceeding_frame->second.length();
    if ((offset + data_length) > frame.offset) {
      DVLOG(1) << "Preceeding frame overlaps new frame: " << offset << " + "
               << data_length << " > " << frame.offset;
      return true;
    }
  }
  return false;
}

bool QuicStreamSequencer::IsDuplicate(const QuicStreamFrame& frame) const {
  // A frame is duplicate if the frame offset is smaller than our bytes consumed
  // or we have stored the frame in our map.
  // TODO(pwestin): Is it possible that a new frame contain more data even if
  // the offset is the same?
  return frame.offset < num_bytes_consumed_ ||
      buffered_frames_.find(frame.offset) != buffered_frames_.end();
}

void QuicStreamSequencer::SetBlockedUntilFlush() {
  blocked_ = true;
}

void QuicStreamSequencer::FlushBufferedFrames() {
  blocked_ = false;
  FrameMap::iterator it = buffered_frames_.find(num_bytes_consumed_);
  while (it != buffered_frames_.end()) {
    DVLOG(1) << "Flushing buffered packet at offset " << it->first;
    string* data = &it->second;
    size_t bytes_consumed = stream_->ProcessRawData(data->c_str(),
                                                    data->size());
    RecordBytesConsumed(bytes_consumed);
    if (MaybeCloseStream()) {
      return;
    }
    if (bytes_consumed > data->size()) {
      stream_->Reset(QUIC_ERROR_PROCESSING_STREAM);  // Programming error
      return;
    } else if (bytes_consumed == data->size()) {
      buffered_frames_.erase(it);
      it = buffered_frames_.find(num_bytes_consumed_);
    } else {
      string new_data = it->second.substr(bytes_consumed);
      buffered_frames_.erase(it);
      buffered_frames_.insert(std::make_pair(num_bytes_consumed_, new_data));
      return;
    }
  }
  MaybeCloseStream();
}

void QuicStreamSequencer::RecordBytesConsumed(size_t bytes_consumed) {
  num_bytes_consumed_ += bytes_consumed;
  num_bytes_buffered_ -= bytes_consumed;

  stream_->AddBytesConsumed(bytes_consumed);
}

}  // namespace net
