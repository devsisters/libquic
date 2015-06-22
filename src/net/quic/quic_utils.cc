// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/quic_utils.h"

#include <ctype.h>
#include <stdint.h>

#include <algorithm>
#include <vector>

#include "base/basictypes.h"
#include "base/containers/adapters.h"
#include "base/logging.h"
#include "base/strings/stringprintf.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "net/quic/quic_write_blocked_list.h"

using base::StringPiece;
using std::string;

namespace net {

// static
uint64 QuicUtils::FNV1a_64_Hash(const char* data, int len) {
  static const uint64 kOffset = UINT64_C(14695981039346656037);
  static const uint64 kPrime = UINT64_C(1099511628211);

  const uint8* octets = reinterpret_cast<const uint8*>(data);

  uint64 hash = kOffset;

  for (int i = 0; i < len; ++i) {
    hash = hash ^ octets[i];
    hash = hash * kPrime;
  }

  return hash;
}

// static
uint128 QuicUtils::FNV1a_128_Hash(const char* data, int len) {
  return FNV1a_128_Hash_Two(data, len, nullptr, 0);
}

// static
uint128 QuicUtils::FNV1a_128_Hash_Two(const char* data1,
                                      int len1,
                                      const char* data2,
                                      int len2) {
  // The two constants are defined as part of the hash algorithm.
  // see http://www.isthe.com/chongo/tech/comp/fnv/
  // 144066263297769815596495629667062367629
  const uint128 kOffset(UINT64_C(7809847782465536322),
                        UINT64_C(7113472399480571277));

  uint128 hash = IncrementalHash(kOffset, data1, len1);
  if (data2 == nullptr) {
    return hash;
  }
  return IncrementalHash(hash, data2, len2);
}

// static
uint128 QuicUtils::IncrementalHash(uint128 hash, const char* data, size_t len) {
  // 309485009821345068724781371
  const uint128 kPrime(16777216, 315);
  const uint8* octets = reinterpret_cast<const uint8*>(data);
  for (size_t i = 0; i < len; ++i) {
    hash  = hash ^ uint128(0, octets[i]);
    hash = hash * kPrime;
  }
  return hash;
}

// static
bool QuicUtils::FindMutualTag(const QuicTagVector& our_tags_vector,
                              const QuicTag* their_tags,
                              size_t num_their_tags,
                              Priority priority,
                              QuicTag* out_result,
                              size_t* out_index) {
  if (our_tags_vector.empty()) {
    return false;
  }
  const size_t num_our_tags = our_tags_vector.size();
  const QuicTag* our_tags = &our_tags_vector[0];

  size_t num_priority_tags, num_inferior_tags;
  const QuicTag* priority_tags;
  const QuicTag* inferior_tags;
  if (priority == LOCAL_PRIORITY) {
    num_priority_tags = num_our_tags;
    priority_tags = our_tags;
    num_inferior_tags = num_their_tags;
    inferior_tags = their_tags;
  } else {
    num_priority_tags = num_their_tags;
    priority_tags = their_tags;
    num_inferior_tags = num_our_tags;
    inferior_tags = our_tags;
  }

  for (size_t i = 0; i < num_priority_tags; i++) {
    for (size_t j = 0; j < num_inferior_tags; j++) {
      if (priority_tags[i] == inferior_tags[j]) {
        *out_result = priority_tags[i];
        if (out_index) {
          if (priority == LOCAL_PRIORITY) {
            *out_index = j;
          } else {
            *out_index = i;
          }
        }
        return true;
      }
    }
  }

  return false;
}

// static
void QuicUtils::SerializeUint128Short(uint128 v, uint8* out) {
  const uint64 lo = Uint128Low64(v);
  const uint64 hi = Uint128High64(v);
  // This assumes that the system is little-endian.
  memcpy(out, &lo, sizeof(lo));
  memcpy(out + sizeof(lo), &hi, sizeof(hi) / 2);
}

#define RETURN_STRING_LITERAL(x) \
case x: \
return #x;

// static
const char* QuicUtils::StreamErrorToString(QuicRstStreamErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_STREAM_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_CONNECTION_ERROR);
    RETURN_STRING_LITERAL(QUIC_ERROR_PROCESSING_STREAM);
    RETURN_STRING_LITERAL(QUIC_MULTIPLE_TERMINATION_OFFSETS);
    RETURN_STRING_LITERAL(QUIC_BAD_APPLICATION_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_STREAM_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_STREAM_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_RST_ACKNOWLEDGEMENT);
    RETURN_STRING_LITERAL(QUIC_STREAM_LAST_ERROR);
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicRstStreamErrorCodes. This can happen when the RstStream
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_RST_STREAM_ERROR_CODE";
}

// static
const char* QuicUtils::ErrorToString(QuicErrorCode error) {
  switch (error) {
    RETURN_STRING_LITERAL(QUIC_NO_ERROR);
    RETURN_STRING_LITERAL(QUIC_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_STREAM_DATA_AFTER_TERMINATION);
    RETURN_STRING_LITERAL(QUIC_INVALID_PACKET_HEADER);
    RETURN_STRING_LITERAL(QUIC_INVALID_FRAME_DATA);
    RETURN_STRING_LITERAL(QUIC_MISSING_PAYLOAD);
    RETURN_STRING_LITERAL(QUIC_INVALID_FEC_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_UNENCRYPTED_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_RST_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_CONNECTION_CLOSE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_GOAWAY_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_WINDOW_UPDATE_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_BLOCKED_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_STOP_WAITING_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_ACK_DATA);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION_NEGOTIATION_PACKET);
    RETURN_STRING_LITERAL(QUIC_INVALID_PUBLIC_RST_PACKET);
    RETURN_STRING_LITERAL(QUIC_DECRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_ENCRYPTION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_PACKET_TOO_LARGE);
    RETURN_STRING_LITERAL(QUIC_PACKET_FOR_NONEXISTENT_STREAM);
    RETURN_STRING_LITERAL(QUIC_PEER_GOING_AWAY);
    RETURN_STRING_LITERAL(QUIC_HANDSHAKE_FAILED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TAGS_OUT_OF_ORDER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_ENTRIES);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_TOO_MANY_REJECTS);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INVALID_VALUE_LENGTH)
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_INTERNAL_ERROR);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_VERSION_NOT_SUPPORTED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_NO_SUPPORT);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_TYPE);
    RETURN_STRING_LITERAL(QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_PRIORITY);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OPEN_STREAMS);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_UNFINISHED_STREAMS);
    RETURN_STRING_LITERAL(QUIC_PUBLIC_RESET);
    RETURN_STRING_LITERAL(QUIC_INVALID_VERSION);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADER_ID);
    RETURN_STRING_LITERAL(QUIC_INVALID_NEGOTIATED_VALUE);
    RETURN_STRING_LITERAL(QUIC_DECOMPRESSION_FAILURE);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_TIMED_OUT);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_OVERALL_TIMED_OUT);
    RETURN_STRING_LITERAL(QUIC_ERROR_MIGRATING_ADDRESS);
    RETURN_STRING_LITERAL(QUIC_PACKET_WRITE_ERROR);
    RETURN_STRING_LITERAL(QUIC_PACKET_READ_ERROR);
    RETURN_STRING_LITERAL(QUIC_INVALID_STREAM_FRAME);
    RETURN_STRING_LITERAL(QUIC_INVALID_HEADERS_STREAM_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA);
    RETURN_STRING_LITERAL(QUIC_FLOW_CONTROL_INVALID_WINDOW);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_IP_POOLED);
    RETURN_STRING_LITERAL(QUIC_PROOF_INVALID);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_DUPLICATE_TAG);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SERVER_CONFIG_EXPIRED);
    RETURN_STRING_LITERAL(QUIC_INVALID_CHANNEL_ID_SIGNATURE);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO);
    RETURN_STRING_LITERAL(QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE);
    RETURN_STRING_LITERAL(QUIC_VERSION_NEGOTIATION_MISMATCH);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS);
    RETURN_STRING_LITERAL(QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS);
    RETURN_STRING_LITERAL(QUIC_CONNECTION_CANCELLED);
    RETURN_STRING_LITERAL(QUIC_BAD_PACKET_LOSS_RATE);
    RETURN_STRING_LITERAL(QUIC_LAST_ERROR);
    // Intentionally have no default case, so we'll break the build
    // if we add errors and don't put them here.
  }
  // Return a default value so that we return this when |error| doesn't match
  // any of the QuicErrorCodes. This can happen when the ConnectionClose
  // frame sent by the peer (attacker) has invalid error code.
  return "INVALID_ERROR_CODE";
}

// static
const char* QuicUtils::EncryptionLevelToString(EncryptionLevel level) {
  switch (level) {
    RETURN_STRING_LITERAL(ENCRYPTION_NONE);
    RETURN_STRING_LITERAL(ENCRYPTION_INITIAL);
    RETURN_STRING_LITERAL(ENCRYPTION_FORWARD_SECURE);
    RETURN_STRING_LITERAL(NUM_ENCRYPTION_LEVELS);
  }
  return "INVALID_ENCRYPTION_LEVEL";
}

// static
const char* QuicUtils::TransmissionTypeToString(TransmissionType type) {
  switch (type) {
    RETURN_STRING_LITERAL(NOT_RETRANSMISSION);
    RETURN_STRING_LITERAL(HANDSHAKE_RETRANSMISSION);
    RETURN_STRING_LITERAL(LOSS_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_UNACKED_RETRANSMISSION);
    RETURN_STRING_LITERAL(ALL_INITIAL_RETRANSMISSION);
    RETURN_STRING_LITERAL(RTO_RETRANSMISSION);
    RETURN_STRING_LITERAL(TLP_RETRANSMISSION);
  }
  return "INVALID_TRANSMISSION_TYPE";
}

// static
string QuicUtils::TagToString(QuicTag tag) {
  char chars[sizeof tag];
  bool ascii = true;
  const QuicTag orig_tag = tag;

  for (size_t i = 0; i < arraysize(chars); i++) {
    chars[i] = static_cast<char>(tag);
    if ((chars[i] == 0 || chars[i] == '\xff') && i == arraysize(chars) - 1) {
      chars[i] = ' ';
    }
    if (!isprint(static_cast<unsigned char>(chars[i]))) {
      ascii = false;
      break;
    }
    tag >>= 8;
  }

  if (ascii) {
    return string(chars, sizeof(chars));
  }

  return base::UintToString(orig_tag);
}

// static
QuicTagVector QuicUtils::ParseQuicConnectionOptions(
    const std::string& connection_options) {
  QuicTagVector options;
  std::vector<std::string> tokens;
  base::SplitString(connection_options, ',', &tokens);
  // Tokens are expected to be no more than 4 characters long, but we
  // handle overflow gracefully.
  for (const std::string& token : tokens) {
    uint32 option = 0;
    for (char token_char : base::Reversed(token)) {
      option <<= 8;
      option |= static_cast<unsigned char>(token_char);
    }
    options.push_back(option);
  }
  return options;
}

// static
string QuicUtils::StringToHexASCIIDump(StringPiece in_buffer) {
  int offset = 0;
  const int kBytesPerLine = 16;   // Max bytes dumped per line
  const char* buf = in_buffer.data();
  int bytes_remaining = in_buffer.size();
  string s;   // our output
  const char* p = buf;
  while (bytes_remaining > 0) {
    const int line_bytes = std::min(bytes_remaining, kBytesPerLine);
    base::StringAppendF(&s, "0x%04x:  ", offset);  // Do the line header
    for (int i = 0; i < kBytesPerLine; ++i) {
      if (i < line_bytes) {
        base::StringAppendF(&s, "%02x", static_cast<unsigned char>(p[i]));
      } else {
        s += "  ";    // two-space filler instead of two-space hex digits
      }
      if (i % 2) s += ' ';
    }
    s += ' ';
    for (int i = 0; i < line_bytes; ++i) {  // Do the ASCII dump
      s+= (p[i] >  32 && p[i] < 127) ? p[i] : '.';
    }

    bytes_remaining -= line_bytes;
    offset += line_bytes;
    p += line_bytes;
    s += '\n';
  }
  return s;
}

// static
QuicPriority QuicUtils::HighestPriority() {
  return QuicWriteBlockedList::kHighestPriority;
}

}  // namespace net
