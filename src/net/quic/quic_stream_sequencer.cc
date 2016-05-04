// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_stream_sequencer.h"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "base/logging.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_clock.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_protocol.h"
#include "net/quic/quic_stream_sequencer_buffer.h"
#include "net/quic/quic_utils.h"
#include "net/quic/reliable_quic_stream.h"

using base::StringPiece;
using std::min;
using std::numeric_limits;
using std::string;

namespace net {

QuicStreamSequencer::QuicStreamSequencer(ReliableQuicStream* quic_stream,
                                         const QuicClock* clock)
    : stream_(quic_stream),
      buffered_frames_(kStreamReceiveWindowLimit),
      close_offset_(numeric_limits<QuicStreamOffset>::max()),
      blocked_(false),
      num_frames_received_(0),
      num_duplicate_frames_received_(0),
      num_early_frames_received_(0),
      clock_(clock),
      ignore_read_data_(false) {}

QuicStreamSequencer::~QuicStreamSequencer() {}

void QuicStreamSequencer::OnStreamFrame(const QuicStreamFrame& frame) {
  ++num_frames_received_;
  const QuicStreamOffset byte_offset = frame.offset;
  const size_t data_len = frame.frame_length;

  if (frame.fin) {
    CloseStreamAtOffset(frame.offset + data_len);
    if (data_len == 0) {
      return;
    }
  }
  size_t bytes_written;
  string error_details;
  QuicErrorCode result = buffered_frames_.OnStreamData(
      byte_offset, StringPiece(frame.frame_buffer, frame.frame_length),
      clock_->ApproximateNow(), &bytes_written, &error_details);
  if (result != QUIC_NO_ERROR) {
    DLOG(WARNING) << QuicUtils::ErrorToString(result);
    DLOG(WARNING) << error_details;
    stream_->CloseConnectionWithDetails(result, error_details);
    return;
  }

  if (bytes_written == 0) {
    ++num_duplicate_frames_received_;
    // Silently ignore duplicates.
    return;
  }

  if (byte_offset > buffered_frames_.BytesConsumed()) {
    ++num_early_frames_received_;
  }

  if (blocked_) {
    return;
  }

  if (byte_offset == buffered_frames_.BytesConsumed()) {
    if (ignore_read_data_) {
      FlushBufferedFrames();
    } else {
      stream_->OnDataAvailable();
    }
  }
}

void QuicStreamSequencer::CloseStreamAtOffset(QuicStreamOffset offset) {
  const QuicStreamOffset kMaxOffset = numeric_limits<QuicStreamOffset>::max();

  // If there is a scheduled close, the new offset should match it.
  if (close_offset_ != kMaxOffset && offset != close_offset_) {
    stream_->Reset(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    return;
  }

  close_offset_ = offset;

  MaybeCloseStream();
}

bool QuicStreamSequencer::MaybeCloseStream() {
  if (blocked_ || !IsClosed()) {
    return false;
  }

  DVLOG(1) << "Passing up termination, as we've processed "
           << buffered_frames_.BytesConsumed() << " of " << close_offset_
           << " bytes.";
  // This will cause the stream to consume the FIN.
  // Technically it's an error if |num_bytes_consumed| isn't exactly
  // equal to |close_offset|, but error handling seems silly at this point.
  if (ignore_read_data_) {
    // The sequencer is discarding stream data and must notify the stream on
    // receipt of a FIN because the consumer won't.
    stream_->OnFinRead();
  } else {
    stream_->OnDataAvailable();
  }
  buffered_frames_.Clear();
  return true;
}

int QuicStreamSequencer::GetReadableRegions(iovec* iov, size_t iov_len) const {
  DCHECK(!blocked_);
  return buffered_frames_.GetReadableRegions(iov, iov_len);
}

bool QuicStreamSequencer::GetReadableRegion(iovec* iov,
                                            QuicTime* timestamp) const {
  DCHECK(!blocked_);
  return buffered_frames_.GetReadableRegion(iov, timestamp);
}

int QuicStreamSequencer::Readv(const struct iovec* iov, size_t iov_len) {
  DCHECK(!blocked_);
  size_t bytes_read = buffered_frames_.Readv(iov, iov_len);
  stream_->AddBytesConsumed(bytes_read);
  return static_cast<int>(bytes_read);
}

bool QuicStreamSequencer::HasBytesToRead() const {
  return buffered_frames_.HasBytesToRead();
}

bool QuicStreamSequencer::IsClosed() const {
  return buffered_frames_.BytesConsumed() >= close_offset_;
}

void QuicStreamSequencer::MarkConsumed(size_t num_bytes_consumed) {
  DCHECK(!blocked_);
  bool result = buffered_frames_.MarkConsumed(num_bytes_consumed);
  if (!result) {
    QUIC_BUG << "Invalid argument to MarkConsumed."
             << " expect to consume: " << num_bytes_consumed
             << ", but not enough bytes available.";
    stream_->Reset(QUIC_ERROR_PROCESSING_STREAM);
    return;
  }
  stream_->AddBytesConsumed(num_bytes_consumed);
}

void QuicStreamSequencer::SetBlockedUntilFlush() {
  blocked_ = true;
}

void QuicStreamSequencer::SetUnblocked() {
  blocked_ = false;
  if (IsClosed() || HasBytesToRead()) {
    stream_->OnDataAvailable();
  }
}

void QuicStreamSequencer::StopReading() {
  if (ignore_read_data_) {
    return;
  }
  ignore_read_data_ = true;
  FlushBufferedFrames();
}

void QuicStreamSequencer::FlushBufferedFrames() {
  DCHECK(ignore_read_data_);
  size_t bytes_flushed = buffered_frames_.FlushBufferedFrames();
  DVLOG(1) << "Flushing buffered data at offset "
           << buffered_frames_.BytesConsumed() << " length " << bytes_flushed
           << " for stream " << stream_->id();
  stream_->AddBytesConsumed(bytes_flushed);
  MaybeCloseStream();
}

size_t QuicStreamSequencer::NumBytesBuffered() const {
  return buffered_frames_.BytesBuffered();
}

QuicStreamOffset QuicStreamSequencer::NumBytesConsumed() const {
  return buffered_frames_.BytesConsumed();
}

}  // namespace net
