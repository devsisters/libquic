#include "base/strings/stringprintf.h"
#include "net/base/ip_address_number.h"

#ifndef WIN32
int _itoa_s(int value, char* buffer, size_t size_in_chars, int radix) {
  const char* format_str;
  if (radix == 10)
    format_str = "%d";
  else if (radix == 16)
    format_str = "%x";
  else
    return EINVAL;

  int written = snprintf(buffer, size_in_chars, format_str, value);
  if (static_cast<size_t>(written) >= size_in_chars) {
    // Output was truncated, or written was negative.
    return EINVAL;
  }
  return 0;
}
// Secure template overloads for these functions
template<size_t N>
inline int _itoa_s(int value, char (&buffer)[N], int radix) {
  return _itoa_s(value, buffer, N, radix);
}
#endif


namespace net {

namespace url {

// Represents a substring for URL parsing.
struct Component {
  Component() : begin(0), len(-1) {}

  // Normal constructor: takes an offset and a length.
  Component(int b, int l) : begin(b), len(l) {}

  int end() const {
    return begin + len;
  }

  // Returns true if this component is valid, meaning the length is given. Even
  // valid components may be empty to record the fact that they exist.
  bool is_valid() const {
    return (len != -1);
  }

  // Returns true if the given component is specified on false, the component
  // is either empty or invalid.
  bool is_nonempty() const {
    return (len > 0);
  }

  void reset() {
    begin = 0;
    len = -1;
  }

  bool operator==(const Component& other) const {
    return begin == other.begin && len == other.len;
  }

  int begin;  // Byte offset in the string of this component.
  int len;    // Will be -1 if the component is unspecified.
};

// Searches for the longest sequence of zeros in |address|, and writes the
// range into |contraction_range|. The run of zeros must be at least 16 bits,
// and if there is a tie the first is chosen.
void ChooseIPv6ContractionRange(const unsigned char address[16],
                                Component* contraction_range) {
  // The longest run of zeros in |address| seen so far.
  Component max_range;

  // The current run of zeros in |address| being iterated over.
  Component cur_range;

  for (int i = 0; i < 16; i += 2) {
    // Test for 16 bits worth of zero.
    bool is_zero = (address[i] == 0 && address[i + 1] == 0);

    if (is_zero) {
      // Add the zero to the current range (or start a new one).
      if (!cur_range.is_valid())
        cur_range = Component(i, 0);
      cur_range.len += 2;
    }

    if (!is_zero || i == 14) {
      // Just completed a run of zeros. If the run is greater than 16 bits,
      // it is a candidate for the contraction.
      if (cur_range.len > 2 && cur_range.len > max_range.len) {
        max_range = cur_range;
      }
      cur_range.reset();
    }
  }
  *contraction_range = max_range;
}

void AppendIPv4Address(const unsigned char address[4], std::stringstream &ss) {
  for (int i = 0; i < 4; i++) {
    char str[16];
    _itoa_s(address[i], str, 10);

    for (int ch = 0; str[ch] != 0; ch++)
      ss << str[ch];

    if (i != 3)
      ss << '.';
  }
}

void AppendIPv6Address(const unsigned char address[16], std::stringstream &ss) {
  // We will output the address according to the rules in:
  // http://tools.ietf.org/html/draft-kawamura-ipv6-text-representation-01#section-4

  // Start by finding where to place the "::" contraction (if any).
  Component contraction_range;
  ChooseIPv6ContractionRange(address, &contraction_range);

  for (int i = 0; i <= 14;) {
    // We check 2 bytes at a time, from bytes (0, 1) to (14, 15), inclusive.
    DCHECK(i % 2 == 0);
    if (i == contraction_range.begin && contraction_range.len > 0) {
      // Jump over the contraction.
      if (i == 0)
        ss << ':';
      ss << ':';
      i = contraction_range.end();
    } else {
      // Consume the next 16 bits from |address|.
      int x = address[i] << 8 | address[i + 1];

      i += 2;

      // Stringify the 16 bit number (at most requires 4 hex digits).
      char str[5];
      _itoa_s(x, str, 16);
      for (int ch = 0; str[ch] != 0; ++ch)
        ss << str[ch];

      // Put a colon after each number, except the last.
      if (i < 16)
        ss << ':';
    }
  }
}

}   // namespace url

std::string IPAddressToString(const uint8_t* address,
                              size_t address_len) {
  std::string str;
  std::stringstream ss;

  if (address_len == kIPv4AddressSize) {
    url::AppendIPv4Address(address, ss);
  } else if (address_len == kIPv6AddressSize) {
    url::AppendIPv6Address(address, ss);
  } else {
    CHECK(false) << "Invalid IP address with length: " << address_len;
  }

  return ss.str();
}

std::string IPAddressToStringWithPort(const uint8_t* address,
                                      size_t address_len,
                                      uint16_t port) {
  std::string address_str = IPAddressToString(address, address_len);

  if (address_len == kIPv6AddressSize) {
    // Need to bracket IPv6 addresses since they contain colons.
    return base::StringPrintf("[%s]:%d", address_str.c_str(), port);
  }
  return base::StringPrintf("%s:%d", address_str.c_str(), port);
}

std::string IPAddressToString(const IPAddressNumber& addr) {
  return IPAddressToString(&addr.front(), addr.size());
}

std::string IPAddressToStringWithPort(const IPAddressNumber& addr,
                                      uint16_t port) {
  return IPAddressToStringWithPort(&addr.front(), addr.size(), port);
}


std::string IPAddressToPackedString(const IPAddressNumber& addr) {
  return std::string(reinterpret_cast<const char *>(&addr.front()),
                     addr.size());
}

namespace {

const unsigned char kIPv4MappedPrefix[] =
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
}

IPAddressNumber ConvertIPv4NumberToIPv6Number(
    const IPAddressNumber& ipv4_number) {
  DCHECK(ipv4_number.size() == 4);

  // IPv4-mapped addresses are formed by:
  // <80 bits of zeros>  + <16 bits of ones> + <32-bit IPv4 address>.
  IPAddressNumber ipv6_number;
  ipv6_number.reserve(16);
  ipv6_number.insert(ipv6_number.end(),
                     kIPv4MappedPrefix,
                     kIPv4MappedPrefix + arraysize(kIPv4MappedPrefix));
  ipv6_number.insert(ipv6_number.end(), ipv4_number.begin(), ipv4_number.end());
  return ipv6_number;
}


}   // namespace net
