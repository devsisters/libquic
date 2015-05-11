// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/reliable_quic_stream.h"

#include "base/logging.h"
#include "net/quic/iovector.h"
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

// Wrapper that aggregates OnAckNotifications for packets sent using
// WriteOrBufferData and delivers them to the original
// QuicAckNotifier::DelegateInterface after all bytes written using
// WriteOrBufferData are acked.  This level of indirection is
// necessary because the delegate interface provides no mechanism that
// WriteOrBufferData can use to inform it that the write required
// multiple WritevData calls or that only part of the data has been
// sent out by the time ACKs start arriving.
class ReliableQuicStream::ProxyAckNotifierDelegate
    : public QuicAckNotifier::DelegateInterface {
 public:
  explicit ProxyAckNotifierDelegate(DelegateInterface* delegate)
      : delegate_(delegate),
        pending_acks_(0),
        wrote_last_data_(false),
        num_retransmitted_packets_(0),
        num_retransmitted_bytes_(0) {
  }

  void OnAckNotification(int num_retransmitted_packets,
                         int num_retransmitted_bytes,
                         QuicTime::Delta delta_largest_observed) override {
    DCHECK_LT(0, pending_acks_);
    --pending_acks_;
    num_retransmitted_packets_ += num_retransmitted_packets;
    num_retransmitted_bytes_ += num_retransmitted_bytes;

    if (wrote_last_data_ && pending_acks_ == 0) {
      delegate_->OnAckNotification(num_retransmitted_packets_,
                                   num_retransmitted_bytes_,
                                   delta_largest_observed);
    }
  }

  void WroteData(bool last_data) {
    DCHECK(!wrote_last_data_);
    ++pending_acks_;
    wrote_last_data_ = last_data;
  }

 protected:
  // Delegates are ref counted.
  ~ProxyAckNotifierDelegate() override {}

 private:
  // Original delegate.  delegate_->OnAckNotification will be called when:
  //   wrote_last_data_ == true and pending_acks_ == 0
  scoped_refptr<DelegateInterface> delegate_;

  // Number of outstanding acks.
  int pending_acks_;

  // True if no pending writes remain.
  bool wrote_last_data_;

  int num_retransmitted_packets_;
  int num_retransmitted_bytes_;

  DISALLOW_COPY_AND_ASSIGN(ProxyAckNotifierDelegate);
};

ReliableQuicStream::PendingData::PendingData(
    string data_in,
    scoped_refptr<ProxyAckNotifierDelegate> delegate_in)
    : data(data_in), offset(0), delegate(delegate_in) {
}

ReliableQuicStream::PendingData::~PendingData() {
}

ReliableQuicStream::ReliableQuicStream(QuicStreamId id, QuicSession* session)
    : sequencer_(this),
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
                       GetInitialStreamFlowControlWindowToSend(session)),
      connection_flow_controller_(session_->flow_controller()),
      stream_contributes_to_connection_flow_control_(true) {
}

ReliableQuicStream::~ReliableQuicStream() {
}

void ReliableQuicStream::OnStreamFrame(const QuicStreamFrame& frame) {
  if (read_side_closed_) {
    DVLOG(1) << ENDPOINT << "Ignoring frame " << frame.stream_id;
    // We don't want to be reading: blackhole the data.
    return;
  }

  if (frame.stream_id != id_) {
    session_->connection()->SendConnectionClose(QUIC_INTERNAL_ERROR);
    return;
  }

  if (frame.fin) {
    fin_received_ = true;
  }

  // This count include duplicate data received.
  size_t frame_payload_size = frame.data.TotalBufferSize();
  stream_bytes_read_ += frame_payload_size;

  // Flow control is interested in tracking highest received offset.
  if (MaybeIncreaseHighestReceivedOffset(frame.offset + frame_payload_size)) {
    // As the highest received offset has changed, we should check to see if
    // this is a violation of flow control.
    if (flow_controller_.FlowControlViolation() ||
        connection_flow_controller_->FlowControlViolation()) {
      session_->connection()->SendConnectionClose(
          QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA);
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
                                            bool from_peer) {
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
  fin_received_ = true;
  CloseReadSide();
}

void ReliableQuicStream::Reset(QuicRstStreamErrorCode error) {
  DCHECK_NE(QUIC_STREAM_NO_ERROR, error);
  stream_error_ = error;
  // Sending a RstStream results in calling CloseStream.
  session()->SendRstStream(id(), error, stream_bytes_written_);
  rst_sent_ = true;
}

void ReliableQuicStream::CloseConnection(QuicErrorCode error) {
  session()->connection()->SendConnectionClose(error);
}

void ReliableQuicStream::CloseConnectionWithDetails(QuicErrorCode error,
                                                    const string& details) {
  session()->connection()->SendConnectionCloseWithDetails(error, details);
}

void ReliableQuicStream::WriteOrBufferData(
    StringPiece data,
    bool fin,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  if (data.empty() && !fin) {
    LOG(DFATAL) << "data.empty() && !fin";
    return;
  }

  if (fin_buffered_) {
    LOG(DFATAL) << "Fin already buffered";
    return;
  }

  scoped_refptr<ProxyAckNotifierDelegate> proxy_delegate;
  if (ack_notifier_delegate != nullptr) {
    proxy_delegate = new ProxyAckNotifierDelegate(ack_notifier_delegate);
  }

  QuicConsumedData consumed_data(0, false);
  fin_buffered_ = fin;

  if (queued_data_.empty()) {
    struct iovec iov(MakeIovec(data));
    consumed_data = WritevData(&iov, 1, fin, proxy_delegate.get());
    DCHECK_LE(consumed_data.bytes_consumed, data.length());
  }

  bool write_completed;
  // If there's unconsumed data or an unconsumed fin, queue it.
  if (consumed_data.bytes_consumed < data.length() ||
      (fin && !consumed_data.fin_consumed)) {
    StringPiece remainder(data.substr(consumed_data.bytes_consumed));
    queued_data_.push_back(PendingData(remainder.as_string(), proxy_delegate));
    write_completed = false;
  } else {
    write_completed = true;
  }

  if ((proxy_delegate.get() != nullptr) &&
      (consumed_data.bytes_consumed > 0 || consumed_data.fin_consumed)) {
    proxy_delegate->WroteData(write_completed);
  }
}

void ReliableQuicStream::OnCanWrite() {
  bool fin = false;
  while (!queued_data_.empty()) {
    PendingData* pending_data = &queued_data_.front();
    ProxyAckNotifierDelegate* delegate = pending_data->delegate.get();
    if (queued_data_.size() == 1 && fin_buffered_) {
      fin = true;
    }
    if (pending_data->offset > 0 &&
        pending_data->offset >= pending_data->data.size()) {
      // This should be impossible because offset tracks the amount of
      // pending_data written thus far.
      LOG(DFATAL) << "Pending offset is beyond available data. offset: "
                  << pending_data->offset
                  << " vs: " << pending_data->data.size();
      return;
    }
    size_t remaining_len = pending_data->data.size() - pending_data->offset;
    struct iovec iov = {
        const_cast<char*>(pending_data->data.data()) + pending_data->offset,
        remaining_len};
    QuicConsumedData consumed_data = WritevData(&iov, 1, fin, delegate);
    if (consumed_data.bytes_consumed == remaining_len &&
        fin == consumed_data.fin_consumed) {
      queued_data_.pop_front();
      if (delegate != nullptr) {
        delegate->WroteData(true);
      }
    } else {
      if (consumed_data.bytes_consumed > 0) {
        pending_data->offset += consumed_data.bytes_consumed;
        if (delegate != nullptr) {
          delegate->WroteData(false);
        }
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
  // If we are connection level flow control blocked, then add the stream
  // to the write blocked list. It will be given a chance to write when a
  // connection level WINDOW_UPDATE arrives.
  if (connection_flow_controller_->IsBlocked() &&
      !flow_controller_.IsBlocked()) {
    session_->MarkWriteBlocked(id(), EffectivePriority());
  }
}

QuicConsumedData ReliableQuicStream::WritevData(
    const struct iovec* iov,
    int iov_count,
    bool fin,
    QuicAckNotifier::DelegateInterface* ack_notifier_delegate) {
  if (write_side_closed_) {
    DLOG(ERROR) << ENDPOINT << "Attempt to write when the write side is closed";
    return QuicConsumedData(0, false);
  }

  // How much data we want to write.
  size_t write_length = TotalIovecLength(iov, iov_count);

  // A FIN with zero data payload should not be flow control blocked.
  bool fin_with_zero_data = (fin && write_length == 0);

  // How much data we are allowed to write from flow control.
  QuicByteCount send_window = flow_controller_.SendWindowSize();
  if (stream_contributes_to_connection_flow_control_) {
    send_window =
        min(send_window, connection_flow_controller_->SendWindowSize());
  }

  if (send_window == 0 && !fin_with_zero_data) {
    // Quick return if we can't send anything.
    MaybeSendBlocked();
    return QuicConsumedData(0, false);
  }

  if (write_length > send_window) {
    // Don't send the FIN if we aren't going to send all the data.
    fin = false;

    // Writing more data would be a violation of flow control.
    write_length = static_cast<size_t>(send_window);
  }

  // Fill an IOVector with bytes from the iovec.
  IOVector data;
  data.AppendIovecAtMostBytes(iov, iov_count, write_length);

  QuicConsumedData consumed_data = session()->WritevData(
      id(), data, stream_bytes_written_, fin, GetFecProtection(),
      ack_notifier_delegate);
  stream_bytes_written_ += consumed_data.bytes_consumed;

  AddBytesSent(consumed_data.bytes_consumed);

  if (consumed_data.bytes_consumed == write_length) {
    if (!fin_with_zero_data) {
      MaybeSendBlocked();
    }
    if (fin && consumed_data.fin_consumed) {
      fin_sent_ = true;
      CloseWriteSide();
    } else if (fin && !consumed_data.fin_consumed) {
      session_->MarkWriteBlocked(id(), EffectivePriority());
    }
  } else {
    session_->MarkWriteBlocked(id(), EffectivePriority());
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

void ReliableQuicStream::OnClose() {
  CloseReadSide();
  CloseWriteSide();

  if (!fin_sent_ && !rst_sent_) {
    // For flow control accounting, we must tell the peer how many bytes we have
    // written on this stream before termination. Done here if needed, using a
    // RST frame.
    DVLOG(1) << ENDPOINT << "Sending RST in OnClose: " << id();
    session_->SendRstStream(id(), QUIC_RST_ACKNOWLEDGEMENT,
                            stream_bytes_written_);
    rst_sent_ = true;
  }

  // We are closing the stream and will not process any further incoming bytes.
  // As there may be more bytes in flight and we need to ensure that both
  // endpoints have the same connection level flow control state, mark all
  // unreceived or buffered bytes as consumed.
  QuicByteCount bytes_to_consume =
      flow_controller_.highest_received_byte_offset() -
      flow_controller_.bytes_consumed();
  AddBytesConsumed(bytes_to_consume);
}

void ReliableQuicStream::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& frame) {
  if (flow_controller_.UpdateSendWindowOffset(frame.byte_offset)) {
    // We can write again!
    // TODO(rjshade): This does not respect priorities (e.g. multiple
    //                outstanding POSTs are unblocked on arrival of
    //                SHLO with initial window).
    // As long as the connection is not flow control blocked, we can write!
    OnCanWrite();
  }
}

bool ReliableQuicStream::MaybeIncreaseHighestReceivedOffset(
    QuicStreamOffset new_offset) {
  uint64 increment =
      new_offset - flow_controller_.highest_received_byte_offset();
  if (!flow_controller_.UpdateHighestReceivedOffset(new_offset)) {
    return false;
  }

  // If |new_offset| increased the stream flow controller's highest received
  // offset, then we need to increase the connection flow controller's value
  // by the incremental difference.
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
  // Only adjust stream level flow controller if we are still reading.
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
