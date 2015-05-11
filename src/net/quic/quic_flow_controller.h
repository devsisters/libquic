// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_FLOW_CONTROLLER_H_
#define NET_QUIC_QUIC_FLOW_CONTROLLER_H_

#include "base/basictypes.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

namespace test {
class QuicFlowControllerPeer;
}  // namespace test

class QuicConnection;

const QuicStreamId kConnectionLevelId = 0;

// QuicFlowController allows a QUIC stream or connection to perform flow
// control. The stream/connection owns a QuicFlowController which keeps track of
// bytes sent/received, can tell the owner if it is flow control blocked, and
// can send WINDOW_UPDATE or BLOCKED frames when needed.
class NET_EXPORT_PRIVATE QuicFlowController {
 public:
  QuicFlowController(QuicConnection* connection,
                     QuicStreamId id,
                     Perspective perspective,
                     QuicStreamOffset send_window_offset,
                     QuicStreamOffset receive_window_offset,
                     QuicByteCount max_receive_window);
  ~QuicFlowController() {}

  // Called when we see a new highest received byte offset from the peer, either
  // via a data frame or a RST.
  // Returns true if this call changes highest_received_byte_offset_, and false
  // in the case where |new_offset| is <= highest_received_byte_offset_.
  bool UpdateHighestReceivedOffset(QuicStreamOffset new_offset);

  // Called when bytes received from the peer are consumed locally. This may
  // trigger the sending of a WINDOW_UPDATE frame using |connection|.
  void AddBytesConsumed(QuicByteCount bytes_consumed);

  // Called when bytes are sent to the peer.
  void AddBytesSent(QuicByteCount bytes_sent);

  // Set a new send window offset.
  // Returns true if this increases send_window_offset_ and is now blocked.
  bool UpdateSendWindowOffset(QuicStreamOffset new_send_window_offset);

  // Returns the current available send window.
  QuicByteCount SendWindowSize() const;

  // Send a BLOCKED frame if appropriate.
  void MaybeSendBlocked();

  // Returns true if flow control send limits have been reached.
  bool IsBlocked() const;

  // Returns true if flow control receive limits have been violated by the peer.
  bool FlowControlViolation();

  QuicByteCount bytes_consumed() const { return bytes_consumed_; }

  QuicStreamOffset highest_received_byte_offset() const {
    return highest_received_byte_offset_;
  }

 private:
  friend class test::QuicFlowControllerPeer;

  // Send a WINDOW_UPDATE frame if appropriate.
  void MaybeSendWindowUpdate();

  // The parent connection, used to send connection close on flow control
  // violation, and WINDOW_UPDATE and BLOCKED frames when appropriate.
  // Not owned.
  QuicConnection* connection_;

  // ID of stream this flow controller belongs to. This can be 0 if this is a
  // connection level flow controller.
  QuicStreamId id_;

  // Tracks if this is owned by a server or a client.
  Perspective perspective_;

  // Track number of bytes received from the peer, which have been consumed
  // locally.
  QuicByteCount bytes_consumed_;

  // The highest byte offset we have seen from the peer. This could be the
  // highest offset in a data frame, or a final value in a RST.
  QuicStreamOffset highest_received_byte_offset_;

  // Tracks number of bytes sent to the peer.
  QuicByteCount bytes_sent_;

  // The absolute offset in the outgoing byte stream. If this offset is reached
  // then we become flow control blocked until we receive a WINDOW_UPDATE.
  QuicStreamOffset send_window_offset_;

  // The absolute offset in the incoming byte stream. The peer should never send
  // us bytes which are beyond this offset.
  QuicStreamOffset receive_window_offset_;

  // Largest size the receive window can grow to.
  QuicByteCount max_receive_window_;

  // Keep track of the last time we sent a BLOCKED frame. We should only send
  // another when the number of bytes we have sent has changed.
  QuicStreamOffset last_blocked_send_window_offset_;

  DISALLOW_COPY_AND_ASSIGN(QuicFlowController);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_FLOW_CONTROLLER_H_
