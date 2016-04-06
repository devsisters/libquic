// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_PARSE_NUMBER_H_
#define NET_BASE_PARSE_NUMBER_H_

#include "base/compiler_specific.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

// This file contains utility functions for parsing numbers, in the context of
// network protocols.
//
// Q: Doesn't //base already provide these in string_number_conversions.h, with
//    functions like base::StringToInt()?
//
// A: Yes, and those functions are used under the hood by these
//    implementations.
//
//    However using the number parsing functions from //base directly in network
//    code can lead to subtle bugs, as the //base versions  are more permissive.
//    For instance "+99" is successfully parsed by base::StringToInt().
//
//    However in the majority of places in //net, a leading plus on a number
//    should be considered invalid. For instance when parsing a host:port pair
//    you wouldn't want to recognize "foo:+99" as having a port of 99. The same
//    issue applies when parsing a content-length header.
//
//    To reduce the risk of such problems, use of these functions over the
//    //base versions.

class GURL;

namespace net {

//  Parses a string representing a decimal number to an |int|. Returns true on
//  success, and fills |*output| with the result. Note that  |*output| is not
//  modified on failure.
//
//  Recognized inputs take the form:
//    1*DIGIT
//
//  Where DIGIT is an ASCII number in the range '0' - '9'
//
//  Note that:
//   * Parsing is locale independent
//   * Leading zeros are allowed (numbers needn't be in minimal encoding)
//   * Inputs that would overflow the output are rejected.
//   * Only accepts integers
//
//  Examples of recognized inputs are:
//    "13"
//    "0"
//    "00013"
//
//  Examples of rejected inputs are:
//    "  13"
//    "-13"
//    "+13"
//    "0x15"
//    "13.3"
NET_EXPORT bool ParseNonNegativeDecimalInt(const base::StringPiece& input,
                                           int* output) WARN_UNUSED_RESULT;

}  // namespace net

#endif  // NET_BASE_PARSE_NUMBER_H_
