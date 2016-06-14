// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Some helpers for quic.

#ifndef NET_QUIC_QUIC_UTILS_H_
#define NET_QUIC_QUIC_UTILS_H_

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "base/macros.h"
#include "base/strings/string_piece.h"
#include "net/base/int128.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

#ifdef _MSC_VER
// MSVC 2013 and prior don't have alignof or aligned(); they have __alignof and
// a __declspec instead.
#define QUIC_ALIGN_OF __alignof
#define QUIC_ALIGNED(X) __declspec(align(X))
#else
#define QUIC_ALIGN_OF alignof
#define QUIC_ALIGNED(X) __attribute__((aligned(X)))
#endif  // _MSC_VER

namespace net {

class NET_EXPORT_PRIVATE QuicUtils {
 public:
  enum Priority {
    LOCAL_PRIORITY,
    PEER_PRIORITY,
  };

  // Returns the 64 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint64_t FNV1a_64_Hash(const char* data, int len);

  // returns the 128 bit FNV1a hash of the data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash(const char* data1, int len1);

  // returns the 128 bit FNV1a hash of the two sequences of data.  See
  // http://www.isthe.com/chongo/tech/comp/fnv/index.html#FNV-param
  static uint128 FNV1a_128_Hash_Two(const char* data1,
                                    int len1,
                                    const char* data2,
                                    int len2);

  // FindMutualTag sets |out_result| to the first tag in the priority list that
  // is also in the other list and returns true. If there is no intersection it
  // returns false.
  //
  // Which list has priority is determined by |priority|.
  //
  // If |out_index| is non-nullptr and a match is found then the index of that
  // match in |their_tags| is written to |out_index|.
  static bool FindMutualTag(const QuicTagVector& our_tags,
                            const QuicTag* their_tags,
                            size_t num_their_tags,
                            Priority priority,
                            QuicTag* out_result,
                            size_t* out_index);

  // SerializeUint128 writes the first 96 bits of |v| in little-endian form
  // to |out|.
  static void SerializeUint128Short(uint128 v, uint8_t* out);

  // Returns the name of the QuicRstStreamErrorCode as a char*
  static const char* StreamErrorToString(QuicRstStreamErrorCode error);

  // Returns the name of the QuicErrorCode as a char*
  static const char* ErrorToString(QuicErrorCode error);

  // Returns the level of encryption as a char*
  static const char* EncryptionLevelToString(EncryptionLevel level);

  // Returns TransmissionType as a char*
  static const char* TransmissionTypeToString(TransmissionType type);

  // TagToString is a utility function for pretty-printing handshake messages
  // that converts a tag to a string. It will try to maintain the human friendly
  // name if possible (i.e. kABCD -> "ABCD"), or will just treat it as a number
  // if not.
  static std::string TagToString(QuicTag tag);

  // Returns the list of QUIC tags represented by the comma separated
  // string in |connection_options|.
  static QuicTagVector ParseQuicConnectionOptions(
      const std::string& connection_options);

  // Given a binary buffer, return a hex+ASCII dump in the style of
  // tcpdump's -X and -XX options:
  // "0x0000:  0090 69bd 5400 000d 610f 0189 0800 4500  ..i.T...a.....E.\n"
  // "0x0010:  001c fb98 4000 4001 7e18 d8ef 2301 455d  ....@.@.~...#.E]\n"
  // "0x0020:  7fe2 0800 6bcb 0bc6 806e                 ....k....n\n"
  static std::string StringToHexASCIIDump(base::StringPiece in_buffer);

  static char* AsChars(unsigned char* data) {
    return reinterpret_cast<char*>(data);
  }

  // Deletes all the sub-frames contained in |frames|.
  static void DeleteFrames(QuicFrames* frames);

  // Deletes all the QuicStreamFrames for the specified |stream_id|.
  static void RemoveFramesForStream(QuicFrames* frames, QuicStreamId stream_id);

  // Deletes and clears all the frames and the packet from serialized packet.
  static void ClearSerializedPacket(SerializedPacket* serialized_packet);

  // Returns a packed representation of |path_id| and |packet_number| in which
  // the highest byte is set to |path_id| and the lower 7 bytes are the lower
  // 7 bytes of |packet_number|.
  static uint64_t PackPathIdAndPacketNumber(QuicPathId path_id,
                                            QuicPacketNumber packet_number);

  // Allocates a new char[] of size |packet.encrypted_length| and copies in
  // |packet.encrypted_buffer|.
  static char* CopyBuffer(const SerializedPacket& packet);

  // Determines and returns change type of address change from |old_address| to
  // |new_address|.
  static PeerAddressChangeType DetermineAddressChangeType(
      const IPEndPoint& old_address,
      const IPEndPoint& new_address);

  // This converts 'num' bytes of binary to a 2*'num'-character hexadecimal
  // representation. Return value: 2*'num' characters of ascii std::string.
  static std::string HexEncode(const char* data, size_t length);
  static std::string HexEncode(base::StringPiece data);

  // This converts 2*'num' hexadecimal characters to 'num' binary data.
  // Return value: 'num' bytes of binary data (via the 'to' argument).
  static std::string HexDecode(const char* data, size_t length);
  static std::string HexDecode(base::StringPiece data);

  // Converts binary data into an ASCII string. Each character in the resulting
  // string is preceeded by a space, and replaced with a '.' if not printable.
  static std::string BinaryToAscii(base::StringPiece binary);

 private:
  DISALLOW_COPY_AND_ASSIGN(QuicUtils);
};

// Utility function that returns an QuicIOVector object wrapped around |str|.
// |str|'s data is stored in |iov|.
inline QuicIOVector MakeIOVector(base::StringPiece str, struct iovec* iov) {
  iov->iov_base = const_cast<char*>(str.data());
  iov->iov_len = static_cast<size_t>(str.size());
  QuicIOVector quic_iov(iov, 1, str.size());
  return quic_iov;
}

}  // namespace net

#endif  // NET_QUIC_QUIC_UTILS_H_
