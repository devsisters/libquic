// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_IOVECTOR_H_
#define NET_QUIC_IOVECTOR_H_

#include <stddef.h>

#include <algorithm>
#include <vector>

#include "base/logging.h"
#include "net/base/iovec.h"
#include "net/base/net_export.h"

namespace net {

// Calculate the total number of bytes in an array of iovec structures.
inline size_t TotalIovecLength(const struct iovec* iov, size_t iovcnt) {
  size_t length = 0;
  if (iov != NULL) {
    for (size_t i = 0; i < iovcnt; ++i) {
      length += iov[i].iov_len;
    }
  }
  return length;
}

// IOVector is a helper class that makes it easier to work with POSIX vector I/O
// struct. It is a thin wrapper by design and thus has no virtual functions and
// all inlined methods. This class makes no assumptions about the ordering of
// the pointer values of the blocks appended, it simply counts bytes when asked
// to consume bytes.
//
// IOVector is a bookkeeping object that collects a description of buffers to
// be read or written together and in order. It does not take ownership of the
// blocks appended.
//
// Because it is used for scatter-gather operations, the order in which the
// buffer blocks are added to the IOVector is important to the client. The
// intended usage pattern is:
//
//   iovector.Append(p0, len0);
//   ...
//   iovector.Append(pn, lenn);
//   int bytes_written = writev(fd, iovector.iovec(), iovector.Size());
//   if (bytes_written > 0)
//     iovector.Consume(bytes_written);
//
// The sequence is the same for readv, except that Consume() in this case is
// used to change the IOVector to only keep track of description of blocks of
// memory not yet written to.
//
// IOVector does not have any method to change the iovec entries that it
// accumulates. This is due to the block merging nature of Append(): we'd like
// to avoid accidentally change an entry that is assembled by two or more
// Append()'s by simply an index access.
//
class NET_EXPORT_PRIVATE IOVector {
 public:
  // Provide a default constructor so it'll never be inhibited by adding other
  // constructors.
  IOVector();
  ~IOVector();

  // Provides a way to convert system call-like iovec representation to
  // IOVector.
  void AppendIovec(const struct iovec* iov, size_t iovcnt) {
    for (size_t i = 0; i < iovcnt; ++i)
      Append(static_cast<char*>(iov[i].iov_base), iov[i].iov_len);
  }

  // Appends at most max_bytes from iovec to the IOVector.
  size_t AppendIovecAtMostBytes(const struct iovec* iov,
                                size_t iovcnt,
                                size_t max_bytes) {
    size_t bytes_appended = 0;
    for (size_t i = 0; i < iovcnt && max_bytes > 0; ++i) {
      const size_t length = std::min(max_bytes, iov[i].iov_len);
      Append(static_cast<char*>(iov[i].iov_base), length);
      max_bytes -= length;
      bytes_appended += length;
    }
    return bytes_appended;
  }

  // Append another block to the IOVector. Since IOVector can be used for read
  // and write, it always takes char*. Clients that writes will need to cast
  // away the constant of the pointer before appending a block.
  void Append(char* buffer, size_t length) {
    if (buffer != nullptr && length > 0) {
      if (iovec_.size() > 0) {
        struct iovec& last = iovec_.back();
        // If the new block is contiguous with the last block, just extend.
        if (static_cast<char*>(last.iov_base) + last.iov_len == buffer) {
          last.iov_len += length;
          return;
        }
      }
      struct iovec tmp = {buffer, length};
      iovec_.push_back(tmp);
    }
  }

  // Same as Append, but doesn't do the tail merge optimization.
  // Intended for testing.
  void AppendNoCoalesce(char* buffer, size_t length) {
    if (buffer != nullptr && length > 0) {
      struct iovec tmp = {buffer, length};
      iovec_.push_back(tmp);
    }
  }

  // Remove a number of bytes from the beginning of the IOVector. Since vector
  // I/O operations always occur at the beginning of the block list, a method
  // to remove bytes at the end is not provided.
  // It returns the number of bytes actually consumed (it'll only be smaller
  // than the requested number if the IOVector contains less data).
  size_t Consume(size_t length) {
    if (length == 0)
      return 0;

    size_t bytes_to_consume = length;
    std::vector<struct iovec>::iterator iter = iovec_.begin();
    std::vector<struct iovec>::iterator end = iovec_.end();
    for (; iter < end && bytes_to_consume >= iter->iov_len; ++iter) {
      bytes_to_consume -= iter->iov_len;
    }
    iovec_.erase(iovec_.begin(), iter);
    if (!iovec_.empty() && bytes_to_consume != 0) {
      iovec_[0].iov_base =
          static_cast<char*>(iovec_[0].iov_base) + bytes_to_consume;
      iovec_[0].iov_len -= bytes_to_consume;
      return length;
    }
    if (iovec_.size() == 0 && bytes_to_consume > 0) {
      LOG(DFATAL) << "Attempting to consume " << bytes_to_consume
                  << " non-existent bytes.";
    }
    // At this point bytes_to_consume is the number of wanted bytes left over
    // after walking through all the iovec entries.
    return length - bytes_to_consume;
  }

  // Identical to Consume, but also copies the portion of the buffer being
  // consumed into |buffer|.  |buffer| must be at least size |length|.  If
  // the IOVector is less than |length|, the method consumes the entire
  // IOVector, logs an error and returns the length consumed.
  size_t ConsumeAndCopy(size_t length, char* buffer) {
    if (length == 0)
      return 0;

    size_t bytes_to_consume = length;
    // First consume all the iovecs which can be consumed completely.
    std::vector<struct iovec>::iterator iter = iovec_.begin();
    std::vector<struct iovec>::iterator end = iovec_.end();
    for (; iter < end && bytes_to_consume >= iter->iov_len; ++iter) {
      memcpy(buffer, iter->iov_base, iter->iov_len);
      bytes_to_consume -= iter->iov_len;
      buffer += iter->iov_len;
    }
    iovec_.erase(iovec_.begin(), iter);
    if (bytes_to_consume == 0) {
      return length;
    }
    if (iovec_.empty()) {
      LOG_IF(DFATAL, bytes_to_consume > 0) << "Attempting to consume "
                                           << bytes_to_consume
                                           << " non-existent bytes.";
      return length - bytes_to_consume;
    }
    // Partially consume the next iovec.
    memcpy(buffer, iovec_[0].iov_base, bytes_to_consume);
    iovec_[0].iov_base =
        static_cast<char*>(iovec_[0].iov_base) + bytes_to_consume;
    iovec_[0].iov_len -= bytes_to_consume;
    return length;
  }

  // TODO(joechan): If capacity is large, swap out for a blank one.
  // Clears the IOVector object to contain no blocks.
  void Clear() { iovec_.clear(); }

  // Swap the guts of two IOVector.
  void Swap(IOVector* other) { iovec_.swap(other->iovec_); }

  // Returns the number of valid blocks in the IOVector (not the number of
  // bytes).
  size_t Size() const { return iovec_.size(); }

  // Returns the total storage used by the IOVector in number of blocks (not
  // the number of bytes).
  size_t Capacity() const { return iovec_.capacity(); }

  // Returns true if there are no blocks in the IOVector.
  bool Empty() const { return iovec_.empty(); }

  // Returns the pointer to the beginning of the iovec to be used for vector
  // I/O operations. If the IOVector has no blocks appened, this function
  // returns NULL.
  struct iovec* iovec() {
    return !Empty() ? &iovec_[0] : NULL;
  }

  // Const version.
  const struct iovec* iovec() const { return !Empty() ? &iovec_[0] : NULL; }

  // Returns a pointer to one past the last byte of the last block. If the
  // IOVector is empty, NULL is returned.
  const char* LastBlockEnd() const {
    return iovec_.size() > 0
               ? static_cast<char*>(iovec_.back().iov_base) +
                     iovec_.back().iov_len
               : NULL;
  }

  // Returns the total number of bytes in the IOVector.
  size_t TotalBufferSize() const { return TotalIovecLength(iovec(), Size()); }

  void Resize(size_t count) { iovec_.resize(count); }

 private:
  std::vector<struct iovec> iovec_;

  // IOVector has value-semantics; copy and assignment are allowed.
  // This class does not explicitly define copy/move constructors or the
  // assignment operator to preserve compiler-generated copy/move constructors
  // and assignment operators. Note that since IOVector does not own the
  // actual buffers that the struct iovecs point to, copies and assignments
  // result in a shallow copy of the buffers; resulting IOVectors will point
  // to the same copy of the underlying data.
};

}  // namespace net

#endif  // NET_QUIC_IOVECTOR_H_
