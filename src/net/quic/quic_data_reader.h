// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUIC_DATA_READER_H_
#define NET_QUIC_QUIC_DATA_READER_H_

#include "base/basictypes.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/net_export.h"

namespace net {

// Used for reading QUIC data. Though there isn't really anything terribly
// QUIC-specific here, it's a helper class that's useful when doing QUIC
// framing.
//
// To use, simply construct a QuicDataReader using the underlying buffer that
// you'd like to read fields from, then call one of the Read*() methods to
// actually do some reading.
//
// This class keeps an internal iterator to keep track of what's already been
// read and each successive Read*() call automatically increments said iterator
// on success. On failure, internal state of the QuicDataReader should not be
// trusted and it is up to the caller to throw away the failed instance and
// handle the error as appropriate. None of the Read*() methods should ever be
// called after failure, as they will also fail immediately.
class NET_EXPORT_PRIVATE QuicDataReader {
 public:
  // Caller must provide an underlying buffer to work on.
  QuicDataReader(const char* data, const size_t len);

  // Empty destructor.
  ~QuicDataReader() {}

  // Reads a 16-bit unsigned integer into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUInt16(uint16* result);

  // Reads a 32-bit unsigned integer into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUInt32(uint32* result);

  // Reads a 48-bit unsigned integer into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUInt48(uint64* result);

  // Reads a 64-bit unsigned integer into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUInt64(uint64* result);

  // Reads a 128-bit unsigned integer into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUInt128(uint128* result);

  // Reads a 16-bit unsigned float into the given output parameter.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadUFloat16(uint64* result);

  // Reads a string prefixed with 16-bit length into the given output parameter.
  //
  // NOTE: Does not copy but rather references strings in the underlying buffer.
  // This should be kept in mind when handling memory management!
  //
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadStringPiece16(base::StringPiece* result);

  // Reads a given number of bytes into the given buffer. The buffer
  // must be of adequate size.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadStringPiece(base::StringPiece* result, size_t len);

  // Returns the remaining payload as a StringPiece.
  //
  // NOTE: Does not copy but rather references strings in the underlying buffer.
  // This should be kept in mind when handling memory management!
  //
  // Forwards the internal iterator.
  base::StringPiece ReadRemainingPayload();

  // Returns the remaining payload as a StringPiece.
  //
  // NOTE: Does not copy but rather references strings in the underlying buffer.
  // This should be kept in mind when handling memory management!
  //
  // DOES NOT forward the internal iterator.
  base::StringPiece PeekRemainingPayload();

  // Reads a given number of bytes into the given buffer. The buffer
  // must be of adequate size.
  // Forwards the internal iterator on success.
  // Returns true on success, false otherwise.
  bool ReadBytes(void* result, size_t size);

  // Returns true if the entirety of the underlying buffer has been read via
  // Read*() calls.
  bool IsDoneReading() const;

  // Returns the number of bytes remaining to be read.
  size_t BytesRemaining() const;

 private:
  // Returns true if the underlying buffer has enough room to read the given
  // amount of bytes.
  bool CanRead(size_t bytes) const;

  // To be called when a read fails for any reason.
  void OnFailure();

  // The data buffer that we're reading from.
  const char* data_;

  // The length of the data buffer that we're reading from.
  const size_t len_;

  // The location of the next read from our data buffer.
  size_t pos_;

  DISALLOW_COPY_AND_ASSIGN(QuicDataReader);
};

}  // namespace net

#endif  // NET_QUIC_QUIC_DATA_READER_H_
