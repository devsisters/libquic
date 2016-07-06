// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_CRYPTO_HANDSHAKE_MESSAGE_H_
#define NET_QUIC_CRYPTO_CRYPTO_HANDSHAKE_MESSAGE_H_

#include <stddef.h>
#include <stdint.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

// An intermediate format of a handshake message that's convenient for a
// CryptoFramer to serialize from or parse into.
class NET_EXPORT_PRIVATE CryptoHandshakeMessage {
 public:
  CryptoHandshakeMessage();
  CryptoHandshakeMessage(const CryptoHandshakeMessage& other);
  ~CryptoHandshakeMessage();

  CryptoHandshakeMessage& operator=(const CryptoHandshakeMessage& other);

  // Clears state.
  void Clear();

  // GetSerialized returns the serialized form of this message and caches the
  // result. Subsequently altering the message does not invalidate the cache.
  const QuicData& GetSerialized() const;

  // MarkDirty invalidates the cache created by |GetSerialized|.
  void MarkDirty();

  // SetValue sets an element with the given tag to the raw, memory contents of
  // |v|.
  template <class T>
  void SetValue(QuicTag tag, const T& v) {
    tag_value_map_[tag] =
        std::string(reinterpret_cast<const char*>(&v), sizeof(v));
  }

  // SetVector sets an element with the given tag to the raw contents of an
  // array of elements in |v|.
  template <class T>
  void SetVector(QuicTag tag, const std::vector<T>& v) {
    if (v.empty()) {
      tag_value_map_[tag] = std::string();
    } else {
      tag_value_map_[tag] = std::string(reinterpret_cast<const char*>(&v[0]),
                                        v.size() * sizeof(T));
    }
  }

  // Returns the message tag.
  QuicTag tag() const { return tag_; }
  // Sets the message tag.
  void set_tag(QuicTag tag) { tag_ = tag; }

  const QuicTagValueMap& tag_value_map() const { return tag_value_map_; }

  void SetStringPiece(QuicTag tag, base::StringPiece value);

  // Erase removes a tag/value, if present, from the message.
  void Erase(QuicTag tag);

  // GetTaglist finds an element with the given tag containing zero or more
  // tags. If such a tag doesn't exist, it returns false. Otherwise it sets
  // |out_tags| and |out_len| to point to the array of tags and returns true.
  // The array points into the CryptoHandshakeMessage and is valid only for as
  // long as the CryptoHandshakeMessage exists and is not modified.
  QuicErrorCode GetTaglist(QuicTag tag,
                           const QuicTag** out_tags,
                           size_t* out_len) const;

  bool GetStringPiece(QuicTag tag, base::StringPiece* out) const;

  // GetNthValue24 interprets the value with the given tag to be a series of
  // 24-bit, length prefixed values and it returns the subvalue with the given
  // index.
  QuicErrorCode GetNthValue24(QuicTag tag,
                              unsigned index,
                              base::StringPiece* out) const;
  QuicErrorCode GetUint32(QuicTag tag, uint32_t* out) const;
  QuicErrorCode GetUint64(QuicTag tag, uint64_t* out) const;

  // size returns 4 (message tag) + 2 (uint16_t, number of entries) +
  // (4 (tag) + 4 (end offset))*tag_value_map_.size() + ∑ value sizes.
  size_t size() const;

  // set_minimum_size sets the minimum number of bytes that the message should
  // consume. The CryptoFramer will add a PAD tag as needed when serializing in
  // order to ensure this. Setting a value of 0 disables padding.
  //
  // Padding is useful in order to ensure that messages are a minimum size. A
  // QUIC server can require a minimum size in order to reduce the
  // amplification factor of any mirror DoS attack.
  void set_minimum_size(size_t min_bytes);

  size_t minimum_size() const;

  // DebugString returns a multi-line, string representation of the message
  // suitable for including in debug output.
  std::string DebugString() const;

 private:
  // GetPOD is a utility function for extracting a plain-old-data value. If
  // |tag| exists in the message, and has a value of exactly |len| bytes then
  // it copies |len| bytes of data into |out|. Otherwise |len| bytes at |out|
  // are zeroed out.
  //
  // If used to copy integers then this assumes that the machine is
  // little-endian.
  QuicErrorCode GetPOD(QuicTag tag, void* out, size_t len) const;

  std::string DebugStringInternal(size_t indent) const;

  QuicTag tag_;
  QuicTagValueMap tag_value_map_;

  size_t minimum_size_;

  // The serialized form of the handshake message. This member is constructed
  // lasily.
  mutable std::unique_ptr<QuicData> serialized_;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_CRYPTO_HANDSHAKE_MESSAGE_H_
