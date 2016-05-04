// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_IP_ADDRESS_NUMBER_H_
#define NET_BASE_IP_ADDRESS_NUMBER_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "base/strings/string_piece.h"
#include "net/base/net_export.h"

namespace net {

// IPAddressNumber is used to represent an IP address's numeric value as an
// array of bytes, from most significant to least significant. This is the
// network byte ordering.
//
// IPv4 addresses will have length 4, whereas IPv6 address will have length 16.
//
// TODO(Martijnc): Remove the IPAddressNumber typedef. New code should use
// IPAddress instead and existing code should be switched over.
// https://crbug.com/496258
typedef std::vector<unsigned char> IPAddressNumber;

static const size_t kIPv4AddressSize = 4;
static const size_t kIPv6AddressSize = 16;

// Returns the string representation of an IP address.
// For example: "192.168.0.1" or "::1". Returns the empty string when |address|
// is invalid.
NET_EXPORT std::string IPAddressToString(const uint8_t* address,
                                         size_t address_len);

// Returns the string representation of an IP address along with its port.
// For example: "192.168.0.1:99" or "[::1]:80". Returns the empty string when
// |address| is invalid (the port will be ignored).
NET_EXPORT std::string IPAddressToStringWithPort(const uint8_t* address,
                                                 size_t address_len,
                                                 uint16_t port);

// Same as IPAddressToString() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToString(const IPAddressNumber& addr);

// Same as IPAddressToStringWithPort() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToStringWithPort(const IPAddressNumber& addr,
                                                 uint16_t port);

// Returns the address as a sequence of bytes in network-byte-order.
NET_EXPORT std::string IPAddressToPackedString(const IPAddressNumber& addr);

// Parses an IP address literal (either IPv4 or IPv6) to its numeric value.
// Returns true on success and fills |ip_number| with the numeric value.
NET_EXPORT bool ParseIPLiteralToNumber(const base::StringPiece& ip_literal,
                                       IPAddressNumber* ip_number);

// Returns number of matching initial bits between the addresses |a1| and |a2|.
unsigned CommonPrefixLength(const IPAddressNumber& a1,
                            const IPAddressNumber& a2);

// Computes the number of leading 1-bits in |mask|.
unsigned MaskPrefixLength(const IPAddressNumber& mask);

}  // namespace net

#endif  // NET_BASE_IP_ADDRESS_NUMBER_H_
