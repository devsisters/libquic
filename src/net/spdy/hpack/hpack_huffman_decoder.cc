// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Decoder for strings encoded using the HPACK Huffman Code (see
// https://httpwg.github.io/specs/rfc7541.html#huffman.code).
//
// This implementation is inspired by the One-Shift algorithm described in
// "On the Implementation of Minimum Redundancy Prefix Codes", by Alistair
// Moffat and Andrew Turpin, 1997.
// See also https://en.wikipedia.org/wiki/Canonical_Huffman_code for background
// on canonical Huffman codes.
//
// This decoder differs from that in .../spdy/hpack/hpack_huffman_table.cc
// as follows:
//   1) It decodes only the code described in RFC7541, where as the older
//      implementation supported any canonical Huffman code provided at run
//      time.
//   2) It uses a fixed amount of memory allocated at build time; it doesn't
//      construct a tree of of decoding tables based on an encoding
//      table provided at run time.
//   3) In benchmarks it runs from 10% to 70% faster, based on the length
//      of the strings (faster for longer strings). Some of the improvements
//      could be back ported, but others are fundamental to the approach.

#include "net/spdy/hpack/hpack_huffman_decoder.h"

#include <bitset>
#include <limits>
#include <utility>

#include "base/logging.h"
#include "net/spdy/hpack/hpack_input_stream.h"

namespace net {
namespace {

typedef HpackHuffmanDecoder::HuffmanWord HuffmanWord;
typedef HpackHuffmanDecoder::HuffmanCodeLength HuffmanCodeLength;

const HuffmanCodeLength kHuffmanWordLength =
    std::numeric_limits<HuffmanWord>::digits;

const HuffmanCodeLength kMinCodeLength = 5;
const HuffmanCodeLength kMaxCodeLength = 30;

const HuffmanWord kInvalidLJCode = ~static_cast<HuffmanWord>(0);
// Length of a code in bits to the first code with that length, left-justified.
// Note that this can be computed from kLengthToFirstCanonical.
const HuffmanWord kLengthToFirstLJCode[] = {
    kInvalidLJCode,  // There are no codes of length 0.
    kInvalidLJCode,  // There are no codes of length 1.
    kInvalidLJCode,  // There are no codes of length 2.
    kInvalidLJCode,  // There are no codes of length 3.
    kInvalidLJCode,  // There are no codes of length 4.
    0x00000000,      // Length 5.
    0x50000000,      // Length 6.
    0xb8000000,      // Length 7.
    0xf8000000,      // Length 8.
    kInvalidLJCode,  // There are no codes of length 9.
    0xfe000000,      // Length 10.
    0xff400000,      // Length 11.
    0xffa00000,      // Length 12.
    0xffc00000,      // Length 13.
    0xfff00000,      // Length 14.
    0xfff80000,      // Length 15.
    kInvalidLJCode,  // There are no codes of length 16.
    kInvalidLJCode,  // There are no codes of length 17.
    kInvalidLJCode,  // There are no codes of length 18.
    0xfffe0000,      // Length 19.
    0xfffe6000,      // Length 20.
    0xfffee000,      // Length 21.
    0xffff4800,      // Length 22.
    0xffffb000,      // Length 23.
    0xffffea00,      // Length 24.
    0xfffff600,      // Length 25.
    0xfffff800,      // Length 26.
    0xfffffbc0,      // Length 27.
    0xfffffe20,      // Length 28.
    kInvalidLJCode,  // There are no codes of length 29.
    0xfffffff0,      // Length 30.
};

// TODO(jamessynge): Determine the performance impact of different types for
// the elements of this array (i.e. a larger type uses more cache, yet might
// better on some architectures).
const uint8_t kInvalidCanonical = 255;
// Maps from length of a code to the first 'canonical symbol' with that length.
const uint8_t kLengthToFirstCanonical[] = {
    kInvalidCanonical,  // Length 0, 0 codes.
    kInvalidCanonical,  // Length 1, 0 codes.
    kInvalidCanonical,  // Length 2, 0 codes.
    kInvalidCanonical,  // Length 3, 0 codes.
    kInvalidCanonical,  // Length 4, 0 codes.
    0,                  // Length 5, 10 codes.
    10,                 // Length 6, 26 codes.
    36,                 // Length 7, 32 codes.
    68,                 // Length 8, 6 codes.
    kInvalidCanonical,  // Length 9, 0 codes.
    74,                 // Length 10, 5 codes.
    79,                 // Length 11, 3 codes.
    82,                 // Length 12, 2 codes.
    84,                 // Length 13, 6 codes.
    90,                 // Length 14, 2 codes.
    92,                 // Length 15, 3 codes.
    kInvalidCanonical,  // Length 16, 0 codes.
    kInvalidCanonical,  // Length 17, 0 codes.
    kInvalidCanonical,  // Length 18, 0 codes.
    95,                 // Length 19, 3 codes.
    98,                 // Length 20, 8 codes.
    106,                // Length 21, 13 codes.
    119,                // Length 22, 26 codes.
    145,                // Length 23, 29 codes.
    174,                // Length 24, 12 codes.
    186,                // Length 25, 4 codes.
    190,                // Length 26, 15 codes.
    205,                // Length 27, 19 codes.
    224,                // Length 28, 29 codes.
    kInvalidCanonical,  // Length 29, 0 codes.
    253,                // Length 30, 4 codes.
};

// Mapping from canonical symbol (0 to 255) to actual symbol.
// clang-format off
const uint8_t kCanonicalToSymbol[] = {
    '0',  '1',  '2',  'a',  'c',  'e',  'i',  'o',
    's',  't',  0x20, '%',  '-',  '.',  '/',  '3',
    '4',  '5',  '6',  '7',  '8',  '9',  '=',  'A',
    '_',  'b',  'd',  'f',  'g',  'h',  'l',  'm',
    'n',  'p',  'r',  'u',  ':',  'B',  'C',  'D',
    'E',  'F',  'G',  'H',  'I',  'J',  'K',  'L',
    'M',  'N',  'O',  'P',  'Q',  'R',  'S',  'T',
    'U',  'V',  'W',  'Y',  'j',  'k',  'q',  'v',
    'w',  'x',  'y',  'z',  '&',  '*',  ',',  ';',
    'X',  'Z',  '!',  '\"', '(',  ')',  '?',  '\'',
    '+',  '|',  '#',  '>',  0x00, '$',  '@',  '[',
    ']',  '~',  '^',  '}',  '<',  '`',  '{',  '\\',
    0xc3, 0xd0, 0x80, 0x82, 0x83, 0xa2, 0xb8, 0xc2,
    0xe0, 0xe2, 0x99, 0xa1, 0xa7, 0xac, 0xb0, 0xb1,
    0xb3, 0xd1, 0xd8, 0xd9, 0xe3, 0xe5, 0xe6, 0x81,
    0x84, 0x85, 0x86, 0x88, 0x92, 0x9a, 0x9c, 0xa0,
    0xa3, 0xa4, 0xa9, 0xaa, 0xad, 0xb2, 0xb5, 0xb9,
    0xba, 0xbb, 0xbd, 0xbe, 0xc4, 0xc6, 0xe4, 0xe8,
    0xe9, 0x01, 0x87, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
    0x8f, 0x93, 0x95, 0x96, 0x97, 0x98, 0x9b, 0x9d,
    0x9e, 0xa5, 0xa6, 0xa8, 0xae, 0xaf, 0xb4, 0xb6,
    0xb7, 0xbc, 0xbf, 0xc5, 0xe7, 0xef, 0x09, 0x8e,
    0x90, 0x91, 0x94, 0x9f, 0xab, 0xce, 0xd7, 0xe1,
    0xec, 0xed, 0xc7, 0xcf, 0xea, 0xeb, 0xc0, 0xc1,
    0xc8, 0xc9, 0xca, 0xcd, 0xd2, 0xd5, 0xda, 0xdb,
    0xee, 0xf0, 0xf2, 0xf3, 0xff, 0xcb, 0xcc, 0xd3,
    0xd4, 0xd6, 0xdd, 0xde, 0xdf, 0xf1, 0xf4, 0xf5,
    0xf6, 0xf7, 0xf8, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0b,
    0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
    0x1e, 0x1f, 0x7f, 0xdc, 0xf9, 0x0a, 0x0d, 0x16,
};
// clang-format on

#if !defined(NDEBUG) || defined(DCHECK_ALWAYS_ON)

// Only used in DLOG.
bool IsEOSPrefix(HuffmanWord bits, HuffmanCodeLength bits_available) {
  if (bits_available == 0) {
    return true;
  }
  // We expect all the bits below the high order |bits_available| bits
  // to be cleared.
  HuffmanWord expected = HuffmanWord(0xffffffff) << (32 - bits_available);
  return bits == expected;
}

#endif  // NDEBUG && !defined(DCHECK_ALWAYS_ON)

}  // namespace

// TODO(jamessynge): Should we read these magic numbers from
// kLengthToFirstLJCode? Would that reduce cache consumption? Slow decoding?
// TODO(jamessynge): Is this being inlined by the compiler? Should we inline
// into DecodeString the tests for code lengths 5 through 8 (> 99% of codes
// according to the HPACK spec)?
HpackHuffmanDecoder::HuffmanCodeLength HpackHuffmanDecoder::CodeLengthOfPrefix(
    HpackHuffmanDecoder::HuffmanWord value) {
  HuffmanCodeLength length;
  if (value < 0xb8000000) {
    if (value < 0x50000000) {
      length = 5;
    } else {
      length = 6;
    }
  } else {
    if (value < 0xfe000000) {
      if (value < 0xf8000000) {
        length = 7;
      } else {
        length = 8;
      }
    } else {
      if (value < 0xffc00000) {
        if (value < 0xffa00000) {
          if (value < 0xff400000) {
            length = 10;
          } else {
            length = 11;
          }
        } else {
          length = 12;
        }
      } else {
        if (value < 0xfffe0000) {
          if (value < 0xfff80000) {
            if (value < 0xfff00000) {
              length = 13;
            } else {
              length = 14;
            }
          } else {
            length = 15;
          }
        } else {
          if (value < 0xffff4800) {
            if (value < 0xfffee000) {
              if (value < 0xfffe6000) {
                length = 19;
              } else {
                length = 20;
              }
            } else {
              length = 21;
            }
          } else {
            if (value < 0xffffea00) {
              if (value < 0xffffb000) {
                length = 22;
              } else {
                length = 23;
              }
            } else {
              if (value < 0xfffffbc0) {
                if (value < 0xfffff800) {
                  if (value < 0xfffff600) {
                    length = 24;
                  } else {
                    length = 25;
                  }
                } else {
                  length = 26;
                }
              } else {
                if (value < 0xfffffff0) {
                  if (value < 0xfffffe20) {
                    length = 27;
                  } else {
                    length = 28;
                  }
                } else {
                  length = 30;
                }
              }
            }
          }
        }
      }
    }
  }
  return length;
}

HuffmanWord HpackHuffmanDecoder::DecodeToCanonical(
    HuffmanCodeLength code_length,
    HuffmanWord bits) {
  DCHECK_LE(kMinCodeLength, code_length);
  DCHECK_LE(code_length, kMaxCodeLength);

  // What is the first left-justified code of length |code_length|?
  HuffmanWord first_lj_code = kLengthToFirstLJCode[code_length];
  DCHECK_NE(kInvalidLJCode, first_lj_code);

  // Which canonical symbol corresponds to the high order |code_length|
  // bits of |first_lj_code|?
  HuffmanWord first_canonical = kLengthToFirstCanonical[code_length];
  DCHECK_NE(kInvalidCanonical, first_canonical);

  // What is the position of the canonical symbol being decoded within
  // the canonical symbols of length |code_length|?
  HuffmanWord ordinal_in_length =
      ((bits - first_lj_code) >> (kHuffmanWordLength - code_length));

  // Combined these two to produce the position of the canonical symbol
  // being decoded within all of the canonical symbols.
  return first_canonical + ordinal_in_length;
}

char HpackHuffmanDecoder::CanonicalToSource(HuffmanWord canonical) {
  DCHECK_LT(canonical, 256u);
  return static_cast<char>(kCanonicalToSymbol[canonical]);
}

// TODO(jamessynge): Maybe further refactorings, including just passing in a
// StringPiece instead of an HpackInputStream, thus avoiding the PeekBits calls,
// and also allowing us to separate the code into portions dealing with long
// strings, and a later portion dealing with the last few bytes of strings.
// TODO(jamessynge): Determine if that is worth it by adding some counters to
// measure the distribution of string sizes seen in practice.
bool HpackHuffmanDecoder::DecodeString(HpackInputStream* in,
                                       std::string* out) {
  out->clear();

  // Load |bits| with the leading bits of the input stream, left justified
  // (i.e. the bits of the first byte are the high-order bits of |bits|,
  // and the bits of the fourth byte are the low-order bits of |bits|).
  // |peeked_success| if there are more bits in |*in| (i.e. the encoding
  // of the string to be decoded is more than 4 bytes).

  auto bits_available_and_bits = in->InitializePeekBits();
  HuffmanCodeLength bits_available = bits_available_and_bits.first;
  HuffmanWord bits = bits_available_and_bits.second;

  // |peeked_success| tracks whether the previous PeekBits call was able to
  // store any new bits into |bits|. For the first pass through the loop below
  // the value false is appropriate:
  //     If we have 32 bits (i.e. the input has at least 4 bytes), then:
  //         |peeked_sucess| is not examined because |code_length| is
  //         at most 30 in the HPACK Huffman Code.
  //     If we have at most 24 bits (i.e. the input has at most 3 bytes), then:
  //         It is possible that the very first |code_length| is greater than
  //         |bits_available|, in which case we need to read peeked_success to
  //         determine whether we should try to read more input, or have already
  //         loaded |bits| with the final bits of the input.
  // After the first loop |peeked_success| has been set by a call to PeekBits.
  bool peeked_success = false;

  while (true) {
    const HuffmanCodeLength code_length = CodeLengthOfPrefix(bits);
    DCHECK_LE(kMinCodeLength, code_length);
    DCHECK_LE(code_length, kMaxCodeLength);
    DVLOG(1) << "bits: 0b" << std::bitset<32>(bits)
             << " (avail=" << bits_available << ")"
             << "    prefix length: " << code_length
             << (code_length > bits_available ? "      *****" : "");
    if (code_length > bits_available) {
      if (!peeked_success) {
        // Unable to read enough input for a match. If only a portion of
        // the last byte remains, this is a successful EOS condition.
        // Note that this does NOT check whether the available bits are all
        // set to 1, which the encoder is required to set at EOS, and the
        // decoder is required to check.
        // TODO(jamessynge): Discuss whether we should enforce this check,
        // as required by the RFC, presumably flag guarded so that we can
        // disable it should it occur a lot. From my testing it appears that
        // our encoder may be doing this wrong. Sigh.
        // TODO(jamessynge): Add a counter for how often the remaining bits
        // are non-zero.
        in->ConsumeByteRemainder();
        DLOG_IF(WARNING,
                (in->HasMoreData() || !IsEOSPrefix(bits, bits_available)))
            << "bits: 0b" << std::bitset<32>(bits)
            << " (avail=" << bits_available << ")"
            << "    prefix length: " << code_length
            << "    HasMoreData: " << in->HasMoreData();
        return !in->HasMoreData();
      }
      // We're dealing with a long code. It *might* be useful to add a special
      // method to HpackInputStream for getting more than "at most 8" bits
      // at a time.
      do {
        peeked_success = in->PeekBits(&bits_available, &bits);
      } while (peeked_success && bits_available < 32);
    } else {
      // Convert from the prefix code of length |code_length| to the
      // canonical symbol (i.e. where the input symbols (bytes) are ordered by
      // increasing code length and then by their increasing uint8 value).
      HuffmanWord canonical = DecodeToCanonical(code_length, bits);

      bits = bits << code_length;
      bits_available -= code_length;
      in->ConsumeBits(code_length);

      if (canonical < 256) {
        out->push_back(CanonicalToSource(canonical));
      } else {
        // Encoder is not supposed to explicity encode the EOS symbol (30
        // 1-bits).
        // TODO(jamessynge): Discuss returning false here, as required by HPACK.
        DCHECK(false) << "EOS explicitly encoded!\n"
                      << "bits: 0b" << std::bitset<32>(bits)
                      << " (avail=" << bits_available << ")"
                      << " prefix length: " << code_length
                      << " canonical: " << canonical;
      }
      // Get some more bits for decoding (up to 8). |peeked_success| is true
      // if we got any bits.
      peeked_success = in->PeekBits(&bits_available, &bits);
    }
    DLOG_IF(WARNING, (VLOG_IS_ON(1) && bits_available < 32 && !peeked_success))
        << "no more peeking possible";
  }
}

}  // namespace net
