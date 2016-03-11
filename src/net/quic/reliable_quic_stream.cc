// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/reliable_quic_stream.h"

#include "base/logging.h"
#include "net/quic/iovector.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_flow_controller.h"
#include "net/quic/quic_session.h"
#include "net/quic/quic_write_blocked_list.h"

using base::StringPiece;
using std::min;
using std::string;

namespace net {

#define ENDPOINT \
  (perspective_ == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace {

struct iovec MakeIovec(StringPiece data) {
  struct iovec iov = {const_cast<char*>(data.data()),
                      static_cast<size_t>(data.size())};
  return iov;
}

size_t GetInitialStreamFlowControlWindowToSend(QuicSession* session) {
  return session->config()->GetInitialStreamFlowControlWindowToSend();
}

size_t GetReceivedFlowControlWindow(QuicSession* session) {
  if (session->config()->HasReceivedInitialStreamFlowControlWindowBytes()) {
    return session->config()->ReceivedInitialStreamFlowControlWindowBytes();
  }

  return kMinimumFlowControlSendWindow;
}

}  // namespace

ReliableQuicStream::PendingData::PendingData(
    string data_in,
    QuicAckListenerInterface* ack_listener_in)
    : data(data_in), offset(0), ack_listener(ack_listener_in) {}

ReliableQuicStream::PendingData::~PendingData() {}

ReliableQuicStream::ReliableQuicStream(QuicStreamId id, QuicSession* session)
    : queued_data_bytes_(0),
      sequencer_(this, session->connection()->clock()),
      id_(id),
      session_(session),
      stream_bytes_read_(0),
      stream_bytes_written_(0),
      stream_error_(QUIC_STREAM_NO_ERROR),
      connection_error_(QUIC_NO_ERROR),
      read_side_closed_(false),
      write_side_closed_(false),
      fin_buffered_(false),
      fin_sent_(false),
      fin_received_(false),
      rst_sent_(false),
      rst_received_(false),
      fec_policy_(FEC_PROTECT_OPTIONAL),
      perspective_(session_->perspective()),
      flow_controller_(session_->connection(),
                       id_,
                       perspective_,
                       GetReceivedFlowControlWindow(session),
                       GetInitialStreamFlowControlWindowToSend(session),
                       session_->flow_controller()->auto_tune_receive_window()),
      connection_flow_controller_(session_->flow_controller()),
      stream_contributes_to_connection_flow_control_(true) {
  SetFromConfig();
}

ReliableQuicStream::~ReliableQuicStream() {}

void ReliableQuicStream::SetFromConfig() {
  if (session_->config()->HasClientSentConnectionOption(kFSTR, perspective_)) {
    fec_policy_ = FEC_PROTECT_ALWAYS;
  }
}

void ReliableQuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  DCHECK_EQ(frame.stream_id, id_);

  DCHECK(!(read_side_closed_ && write_side_closed_));

  if (frame.fin) {
    fin_received_ = true;
    if (fin_sent_) {
      session_->StreamDraining(id_);
    }
  }

  if (read_side_closed_) {
    DVLOG(1) << ENDPOINT << "Ignoring data in frame " << frame.stream_id;
    // The subclass does not want to read data:  blackhole the data.
    return;
  }

  // This count includes duplicate data received.
  size_t frame_payload_size = frame.frame_length;
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  if (MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, check to see if this is a
    // violation of flow control.
    if (flow_controller_.FlowControlViolation() ||
        connection_flow_controller_->FlowControlViolation()) {
      session_->connection()->SendConnectionCloseWithDetails(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA,
          "Flow control violation after increasing offset");
      return;
    }
  }

  sequencer_.OnStreamFrame(frame);
}

int ReliableQuicStream::num_frames_received() const {
  return sequencer_.num_frames_received();
}

int ReliableQuicStream::num_early_frames_received() const {
  return sequencer_.num_early_frames_received();
}

int ReliableQuicStream::num_duplicate_frames_received() const {
  return sequencer_.num_duplicate_frames_received();
}

void ReliableQuicStream::OnStreamReset(const QuicRstStreamFrame& frame) {
  rst_received_ = true;
  MaybeIncreaseHighestReceivedOffset(frame.byte_offset);

  stream_error_ = frame.error_code;
  CloseWriteSide();
  CloseReadSide();
}

void ReliableQuicStream::OnConnectionClosed(QuicErrorCode error,
                                            ConnectionCloseSource /*source*/) {
  if (read_side_closed_ && write_side_closed_) {
    return;
  }
  if (error != QUIC_NO_ERROR) {
    stream_error_ = QUIC_STREAM_CONNECTION_ERROR;
    connection_error_ = error;
  }

  CloseWriteSide();
  CloseReadSide();
}

void ReliableQuicStream::OnFinRead() {
  DCHECK(sequencer_.IsClosed());
  // OnFinRead can be called due to a FIN flag in a headers block, so there may
  // have been no OnStreamFrame call with a FIN in the frame.
  fin_received_ = true;
  // If fin_sent_ is true, then CloseWriteSide has already been called, and the
  // stream will be destroyed by CloseReadSide, so don't need to call
  // StreamDraining.
  CloseReadSide();
}

void ReliableQuicStream::Reset(QuicRstStreamErrorCode error) {
  stream_error_ = error;
  // Sending a RstStream results in calling CloseStream.
  session()->SendRstStream(id(), error, stream_bytes_written_);
  rst_sent_ = true;
}

void ReliableQuicStream::CloseConnectionWithDetails(QuicErrorCode error,
                                                    const string& details) {
  session()->connection()->SendConnectionCloseWithDetails(error, details);
}

void ReliableQuicStream::WriteOrBufferData(
    StringPiece data,
    bool fin,
    QuicAckListenerInterface* ack_listener) {
  if (data.empty() && !fin) {
    QUIC_BUG << "data.empty() && !fin";
    return;
  }

  if (fin_buffered_) {
    QUIC_BUG << "Fin already buffered";
    return;
  }
  if (write_side_closed_) {
    DLOG(ERROR) << ENDPOINT << "Attempt to write when the write side is closed";
    return;
  }

  QuicConsumedData consumed_data(0, false);
  fin_buffered_ = fin;

  if (queued_data_.empty()) {
    struct iovec iov(MakeIovec(data));
    consumed_data = WritevData(&iov, 1, fin, ack_listener);
    DCHECK_LE(consumed_data.bytes_consumed, data.length());
  }

  // If there's unconsumed data or an unconsumed fin, queue it.
  if (consumed_data.bytes_consumed < data.length() ||
      (fin && !consumed_data.fin_consumed)) {
    StringPiece remainder(data.substr(consumed_data.bytes_consumed));
    queued_data_bytes_ += remainder.size();
    queued_data_.emplace_back(remainder.as_string(), ack_listener);
  }
}

void ReliableQuicStream::OnCanWrite() {
  bool fin = false;
  while (!queued_data_.empty()) {
    PendingData* pending_data = &queued_data_.front();
    QuicAckListenerInterface* ack_listener = pending_data->ack_listener.get();
    if (queued_data_.size() == 1 && fin_buffered_) {
      fin = true;
    }
    if (pending_data->offset > 0 &&
        pending_data->offset >= pending_data->data.size()) {
      // This should be impossible because offset tracks the amount of
      // pending_data written thus far.
      QUIC_BUG << "Pending offset is beyond available data. offset: "
               << pending_data->offset << " vs: " << pending_data->data.size();
      return;
    }
    size_t remaining_len = pending_data->data.size() - pending_data->offset;
    struct iovec iov = {
        const_cast<char*>(pending_data->data.data()) + pending_data->offset,
        remaining_len};
    QuicConsumedData consumed_data = WritevData(&iov, 1, fin, ack_listener);
    queued_data_bytes_ -= consumed_data.bytes_consumed;
    if (consumed_data.bytes_consumed == remaining_len &&
        fin == consumed_data.fin_consumed) {
      queued_data_.pop_front();
    } else {
      if (consumed_data.bytes_consumed > 0) {
        pending_data->offset += consumed_data.bytes_consumed;
      }
      break;
    }
  }
}

void ReliableQuicStream::MaybeSendBlocked() {
  flow_controller_.MaybeSendBlocked();
  if (!stream_contributes_to_connection_flow_control_) {
    return;
  }
  connection_flow_controller_->MaybeSendBlocked();
  // If the stream is blocked by connection-level flow control but not by
  // stream-level flow control, add the stream to the write blocked list so that
  // the stream will be given a chance to write when a connection-level
  // WINDOW_UPDATE arrives.
  if (connection_flow_controller_->IsBlocked() &&
      !flow_controller_.IsBlocked()) {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
}

QuicConsumedData ReliableQuicStream::WritevData(
    const struct iovec* iov,
    int iov_count,
    bool fin,
    QuicAckListenerInterface* ack_listener) {
  if (write_side_closed_) {
    DLOG(ERROR) << ENDPOINT << "Attempt to write when the write side is closed";
    return QuicConsumedData(0, false);
  }

  // How much data was provided.
  size_t write_length = TotalIovecLength(iov, iov_count);

  // A FIN with zero data payload should not be flow control blocked.
  bool fin_with_zero_data = (fin && write_length == 0);

  // How much data flow control permits to be written.
  QuicByteCount send_window = flow_controller_.SendWindowSize();
  if (stream_contributes_to_connection_flow_control_) {
    send_window =
        min(send_window, connection_flow_controller_->SendWindowSize());
  }

  if (FLAGS_quic_cede_correctly && session_->ShouldYield(id())) {
    session_->MarkConnectionLevelWriteBlocked(id());
    return QuicConsumedData(0, false);
  }

  if (send_window == 0 && !fin_with_zero_data) {
    // Quick return if nothing can be sent.
    MaybeSendBlocked();
    return QuicConsumedData(0, false);
  }

  if (write_length > send_window) {
    // Don't send the FIN unless all the data will be sent.
    fin = false;

    // Writing more data would be a violation of flow control.
    write_length = static_cast<size_t>(send_window);
  }

  QuicConsumedData consumed_data = session()->WritevData(
      id(), QuicIOVector(iov, iov_count, write_length), stream_bytes_written_,
      fin, GetFecProtection(), ack_listener);
  stream_bytes_written_ += consumed_data.bytes_consumed;

  AddBytesSent(consumed_data.bytes_consumed);

  // The write may have generated a write error causing this stream to be
  // closed. If so, simply return without marking the stream write blocked.
  if (write_side_closed_) {
    return consumed_data;
  }

  if (consumed_data.bytes_consumed == write_length) {
    if (!fin_with_zero_data) {
      MaybeSendBlocked();
    }
    if (fin && consumed_data.fin_consumed) {
      fin_sent_ = true;
      if (fin_received_) {
        session_->StreamDraining(id_);
      }
      CloseWriteSide();
    } else if (fin && !consumed_data.fin_consumed) {
      session_->MarkConnectionLevelWriteBlocked(id());
    }
  } else {
    session_->MarkConnectionLevelWriteBlocked(id());
  }
  return consumed_data;
}

FecProtection ReliableQuicStream::GetFecProtection() {
  return fec_policy_ == FEC_PROTECT_ALWAYS ? MUST_FEC_PROTECT : MAY_FEC_PROTECT;
}

void ReliableQuicStream::CloseReadSide() {
  if (read_side_closed_) {
    return;
  }
  DVLOG(1) << ENDPOINT << "Done reading from stream " << id();

  read_side_closed_ = true;
  if (write_side_closed_) {
    DVLOG(1) << ENDPOINT << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

void ReliableQuicStream::CloseWriteSide() {
  if (write_side_closed_) {
    return;
  }
  DVLOG(1) << ENDPOINT << "Done writing to stream " << id();

  write_side_closed_ = true;
  if (read_side_closed_) {
    DVLOG(1) << ENDPOINT << "Closing stream: " << id();
    session_->CloseStream(id());
  }
}

bool ReliableQuicStream::HasBufferedData() const {
  return !queued_data_.empty();
}

QuicVersion ReliableQuicStream::version() const {
  return session_->connection()->version();
}

void ReliableQuicStream::StopReading() {
  DVLOG(1) << ENDPOINT << "Stop reading from stream " << id();
  sequencer_.StopReading();
}

void ReliableQuicStream::OnClose() {
  CloseReadSide();
  CloseWriteSide();

  if (!fin_sent_ && !rst_sent_) {
    // For flow control accounting, tell the peer how many bytes have been
    // written on this stream before termination. Done here if needed, using a
    // RST_STREAM frame.
    DVLOG(1) << ENDPOINT << "Sending RST_STREAM in OnClose: " << id();
    session_->SendRstStream(id(), QUIC_RST_ACKNOWLEDGEMENT,
                            stream_bytes_written_);
    rst_sent_ = true;
  }

  // The stream is being closed and will not process any further incoming bytes.
  // As there may be more bytes in flight, to ensure that both endpoints have
  // the same connection level flow control state, mark all unreceived or
  // buffered bytes as consumed.
  QuicByteCount bytes_to_consume =
      flow_controller_.highest_received_byte_offset() -
      flow_controller_.bytes_consumed();
  AddBytesConsumed(bytes_to_consume);
}

void ReliableQuicStream::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  if (flow_controller_.UpdateSendWindowOffset(frame.byte_offset)) {
    // Writing can be done again!
    // TODO(rjshade): This does not respect priorities (e.g. multiple
    //                outstanding POSTs are unblocked on arrival of
    //                SHLO with initial window).
    // As long as the connection is not flow control blocked, write on!
    OnCanWrite();
  }
}

bool ReliableQuicStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  uint64_t increment =
      new_offset - flow_controller_.highest_received_byte_offset();
  if (!flow_controller_.UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, increase the connection flow controller's value by the incremental
  // difference.
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->UpdateHighestReceivedOffset(
        connection_flow_controller_->highest_received_byte_offset() +
        increment);
  }
  return true;
}

void ReliableQuicStream::AddBytesSent(QuicByteCount bytes) {
  flow_controller_.AddBytesSent(bytes);
  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesSent(bytes);
  }
}

void ReliableQuicStream::AddBytesConsumed(QuicByteCount bytes) {
  // Only adjust stream level flow controller if still reading.
  if (!read_side_closed_) {
    flow_controller_.AddBytesConsumed(bytes);
  }

  if (stream_contributes_to_connection_flow_control_) {
    connection_flow_controller_->AddBytesConsumed(bytes);
  }
}

void ReliableQuicStream::UpdateSendWindowOffset(QuicStreamOffset new_window) {
  if (flow_controller_.UpdateSendWindowOffset(new_window)) {
    OnCanWrite();
  }
}

}  // namespace net
