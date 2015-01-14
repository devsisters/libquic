#ifndef NET_BASE_NET_UTIL_H_
#define NET_BASE_NET_UTIL_H_

#include "build/build_config.h"

#if defined(OS_WIN)
#include <windows.h>
#include <ws2tcpip.h>
#elif defined(OS_POSIX)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <string>
#include <vector>

#include "base/basictypes.h"
#include "net/base/address_family.h"
#include "net/base/net_export.h"

namespace url {
// Component ------------------------------------------------------------------

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
}   // namespace url

namespace net {
// IPAddressNumber is used to represent an IP address's numeric value as an
// array of bytes, from most significant to least significant. This is the
// network byte ordering.
//
// IPv4 addresses will have length 4, whereas IPv6 address will have length 16.
typedef std::vector<unsigned char> IPAddressNumber;
typedef std::vector<IPAddressNumber> IPAddressList;

static const size_t kIPv4AddressSize = 4;
static const size_t kIPv6AddressSize = 16;
#if defined(OS_WIN)
// Bluetooth address size. Windows Bluetooth is supported via winsock.
static const size_t kBluetoothAddressSize = 6;
#endif

// Returns AddressFamily of the address.
NET_EXPORT_PRIVATE AddressFamily GetAddressFamily(
    const IPAddressNumber& address);

// Extracts the IP address and port portions of a sockaddr. |port| is optional,
// and will not be filled in if NULL.
bool GetIPAddressFromSockAddr(const struct sockaddr* sock_addr,
                              socklen_t sock_addr_len,
                              const unsigned char** address,
                              size_t* address_len,
                              uint16* port);

// Same as IPAddressToString() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToString(const IPAddressNumber& addr);

// Same as IPAddressToStringWithPort() but for an IPAddressNumber.
NET_EXPORT std::string IPAddressToStringWithPort(
    const IPAddressNumber& addr, uint16 port);

// Returns the address as a sequence of bytes in network-byte-order.
NET_EXPORT std::string IPAddressToPackedString(const IPAddressNumber& addr);

}



#endif  // NET_BASE_NET_UTIL_H_
