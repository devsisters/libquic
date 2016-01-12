// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CRYPTO_FRAMER_H_
#define NET_QUIC_CRYPTO_CRYPTO_FRAMER_H_

#include <stddef.h>
#include <stdint.h>

#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/crypto/crypto_handshake_message.h"
#include "net/quic/quic_protocol.h"

namespace net {

class CryptoFramer;
class QuicData;
class QuicDataReader;
class QuicDataWriter;

class NET_EXPORT_PRIVATE CryptoFramerVisitorInterface {
 public:
  virtual ~CryptoFramerVisitorInterface() {}

  // Called if an error is detected.
  virtual void OnError(CryptoFramer* framer) = 0;

  // Called when a complete handshake message has been parsed.
  virtual void OnHandshakeMessage(const CryptoHandshakeMessage& message) = 0;
};

// A class for framing the crypto messages that are exchanged in a QUIC
// session.
class NET_EXPORT_PRIVATE CryptoFramer {
 public:
  CryptoFramer();

  virtual ~CryptoFramer();

  // ParseMessage parses exactly one message from the given StringPiece. If
  // there is an error, the message is truncated, or the message has trailing
  // garbage then nullptr will be returned.
  static CryptoHandshakeMessage* ParseMessage(base::StringPiece in);

  // Set callbacks to be called from the framer.  A visitor must be set, or
  // else the framer will crash.  It is acceptable for the visitor to do
  // nothing.  If this is called multiple times, only the last visitor
  // will be used.  |visitor| will be owned by the framer.
  void set_visitor(CryptoFramerVisitorInterface* visitor) {
    visitor_ = visitor;
  }

  QuicErrorCode error() const { return error_; }
  const std::string& error_detail() const { return error_detail_; }

  // Processes input data, which must be delivered in order. Returns
  // false if there was an error, and true otherwise.
  bool ProcessInput(base::StringPiece input);

  // Returns the number of bytes of buffered input data remaining to be
  // parsed.
  size_t InputBytesRemaining() const { return buffer_.length(); }

  // Returns a new QuicData owned by the caller that contains a serialized
  // |message|, or nullptr if there was an error.
  static QuicData* ConstructHandshakeMessage(
      const CryptoHandshakeMessage& message);

 private:
  // Clears per-message state.  Does not clear the visitor.
  void Clear();

  // Process does does the work of |ProcessInput|, but returns an error code,
  // doesn't set error_ and doesn't call |visitor_->OnError()|.
  QuicErrorCode Process(base::StringPiece input);

  static bool WritePadTag(QuicDataWriter* writer,
                          size_t pad_length,
                          uint32_t* end_offset);

  // Represents the current state of the parsing state machine.
  enum CryptoFramerState {
    STATE_READING_TAG,
    STATE_READING_NUM_ENTRIES,
    STATE_READING_TAGS_AND_LENGTHS,
    STATE_READING_VALUES
  };

  // Visitor to invoke when messages are parsed.
  CryptoFramerVisitorInterface* visitor_;
  // Last error.
  QuicErrorCode error_;
  // Remaining unparsed data.
  std::string buffer_;
  // Current state of the parsing.
  CryptoFramerState state_;
  // The message currently being parsed.
  CryptoHandshakeMessage message_;
  // The issue which caused |error_|
  std::string error_detail_;
  // Number of entires in the message currently being parsed.
  uint16_t num_entries_;
  // tags_and_lengths_ contains the tags that are currently being parsed and
  // their lengths.
  std::vector<std::pair<QuicTag, size_t>> tags_and_lengths_;
  // Cumulative length of all values in the message currently being parsed.
  size_t values_len_;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CRYPTO_FRAMER_H_
