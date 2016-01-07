// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/net_util.h"

#include <errno.h>

#include <algorithm>
#include <limits>
#include <string>

#include "build/build_config.h"

#if defined(OS_WIN)
#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2bth.h>
#pragma comment(lib, "iphlpapi.lib")
#elif defined(OS_POSIX)
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#if !defined(OS_NACL)
#include <net/if.h>
#if !defined(OS_ANDROID)
#include <ifaddrs.h>
#endif  // !defined(OS_NACL)
#endif  // !defined(OS_ANDROID)
#endif  // defined(OS_POSIX)

#include "base/json/string_escape.h"
#include "base/logging.h"
#include "base/strings/string_piece.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "base/sys_byteorder.h"
#include "base/values.h"
#include "net/base/ip_address_number.h"
#include "url/gurl.h"
#include "url/third_party/mozilla/url_parse.h"
#include "url/url_canon.h"
#include "url/url_canon_ip.h"

#if defined(OS_ANDROID)
#include "net/android/network_library.h"
#endif
#if defined(OS_WIN)
#include "net/base/winsock_init.h"
#endif

namespace net {

namespace {

#if 0
std::string NormalizeHostname(base::StringPiece host) {
  std::string result = base::ToLowerASCII(host);
  if (!result.empty() && *result.rbegin() == '.')
    result.resize(result.size() - 1);
  return result;
}
#endif

#if 0
bool IsNormalizedLocalhostTLD(const std::string& host) {
  return base::EndsWith(host, ".localhost", base::CompareCase::SENSITIVE);
}
#endif

#if 0
// |host| should be normalized.
bool IsLocalHostname(const std::string& host) {
  return host == "localhost" || host == "localhost.localdomain" ||
         IsNormalizedLocalhostTLD(host);
}
#endif

#if 0
// |host| should be normalized.
bool IsLocal6Hostname(const std::string& host) {
  return host == "localhost6" || host == "localhost6.localdomain6";
}
#endif

}  // namespace

#if 0
std::string CanonicalizeHost(const std::string& host,
                             url::CanonHostInfo* host_info) {
  // Try to canonicalize the host.
  const url::Component raw_host_component(0, static_cast<int>(host.length()));
  std::string canon_host;
  url::StdStringCanonOutput canon_host_output(&canon_host);
  url::CanonicalizeHostVerbose(host.c_str(), raw_host_component,
                               &canon_host_output, host_info);

  if (host_info->out_host.is_nonempty() &&
      host_info->family != url::CanonHostInfo::BROKEN) {
    // Success!  Assert that there's no extra garbage.
    canon_host_output.Complete();
    DCHECK_EQ(host_info->out_host.len, static_cast<int>(canon_host.length()));
  } else {
    // Empty host, or canonicalization failed.  We'll return empty.
    canon_host.clear();
  }

  return canon_host;
}
#endif

#if 0
std::string GetDirectoryListingHeader(const base::string16& title) {
  static const base::StringPiece header(
      NetModule::GetResource(IDR_DIR_HEADER_HTML));
  // This can be null in unit tests.
  DLOG_IF(WARNING, header.empty()) <<
      "Missing resource: directory listing header";

  std::string result;
  if (!header.empty())
    result.assign(header.data(), header.size());

  result.append("<script>start(");
  base::EscapeJSONString(title, true, &result);
  result.append(");</script>\n");

  return result;
}
#endif

inline bool IsHostCharAlphanumeric(char c) {
  // We can just check lowercase because uppercase characters have already been
  // normalized.
  return ((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9'));
}

bool IsCanonicalizedHostCompliant(const std::string& host) {
  if (host.empty())
    return false;

  bool in_component = false;
  bool most_recent_component_started_alphanumeric = false;

  for (std::string::const_iterator i(host.begin()); i != host.end(); ++i) {
    const char c = *i;
    if (!in_component) {
      most_recent_component_started_alphanumeric = IsHostCharAlphanumeric(c);
      if (!most_recent_component_started_alphanumeric && (c != '-') &&
          (c != '_')) {
        return false;
      }
      in_component = true;
    } else if (c == '.') {
      in_component = false;
    } else if (!IsHostCharAlphanumeric(c) && (c != '-') && (c != '_')) {
      return false;
    }
  }

  return most_recent_component_started_alphanumeric;
}

int SetNonBlocking(int fd) {
#if defined(OS_WIN)
  unsigned long no_block = 1;
  return ioctlsocket(fd, FIONBIO, &no_block);
#elif defined(OS_POSIX)
  int flags = fcntl(fd, F_GETFL, 0);
  if (-1 == flags)
    return flags;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

#if 0
bool ParseHostAndPort(std::string::const_iterator host_and_port_begin,
                      std::string::const_iterator host_and_port_end,
                      std::string* host,
                      int* port) {
  if (host_and_port_begin >= host_and_port_end)
    return false;

  // When using url, we use char*.
  const char* auth_begin = &(*host_and_port_begin);
  int auth_len = host_and_port_end - host_and_port_begin;

  url::Component auth_component(0, auth_len);
  url::Component username_component;
  url::Component password_component;
  url::Component hostname_component;
  url::Component port_component;

  url::ParseAuthority(auth_begin, auth_component, &username_component,
      &password_component, &hostname_component, &port_component);

  // There shouldn't be a username/password.
  if (username_component.is_valid() || password_component.is_valid())
    return false;

  if (!hostname_component.is_nonempty())
    return false;  // Failed parsing.

  int parsed_port_number = -1;
  if (port_component.is_nonempty()) {
    parsed_port_number = url::ParsePort(auth_begin, port_component);

    // If parsing failed, port_number will be either PORT_INVALID or
    // PORT_UNSPECIFIED, both of which are negative.
    if (parsed_port_number < 0)
      return false;  // Failed parsing the port number.
  }

  if (port_component.len == 0)
    return false;  // Reject inputs like "foo:"

  unsigned char tmp_ipv6_addr[16];

  // If the hostname starts with a bracket, it is either an IPv6 literal or
  // invalid. If it is an IPv6 literal then strip the brackets.
  if (hostname_component.len > 0 &&
      auth_begin[hostname_component.begin] == '[') {
    if (auth_begin[hostname_component.end() - 1] == ']' &&
        url::IPv6AddressToNumber(
            auth_begin, hostname_component, tmp_ipv6_addr)) {
      // Strip the brackets.
      hostname_component.begin++;
      hostname_component.len -= 2;
    } else {
      return false;
    }
  }

  // Pass results back to caller.
  host->assign(auth_begin + hostname_component.begin, hostname_component.len);
  *port = parsed_port_number;

  return true;  // Success.
}

bool ParseHostAndPort(const std::string& host_and_port,
                      std::string* host,
                      int* port) {
  return ParseHostAndPort(
      host_and_port.begin(), host_and_port.end(), host, port);
}
#endif

#if 0
std::string GetHostAndPort(const GURL& url) {
  // For IPv6 literals, GURL::host() already includes the brackets so it is
  // safe to just append a colon.
  return base::StringPrintf("%s:%d", url.host().c_str(),
                            url.EffectiveIntPort());
}

std::string GetHostAndOptionalPort(const GURL& url) {
  // For IPv6 literals, GURL::host() already includes the brackets
  // so it is safe to just append a colon.
  if (url.has_port())
    return base::StringPrintf("%s:%s", url.host().c_str(), url.port().c_str());
  return url.host();
}
#endif

#if 0
bool IsHostnameNonUnique(const std::string& hostname) {
  // CanonicalizeHost requires surrounding brackets to parse an IPv6 address.
  const std::string host_or_ip = hostname.find(':') != std::string::npos ?
      "[" + hostname + "]" : hostname;
  url::CanonHostInfo host_info;
  std::string canonical_name = CanonicalizeHost(host_or_ip, &host_info);

  // If canonicalization fails, then the input is truly malformed. However,
  // to avoid mis-reporting bad inputs as "non-unique", treat them as unique.
  if (canonical_name.empty())
    return false;

  // If |hostname| is an IP address, check to see if it's in an IANA-reserved
  // range.
  if (host_info.IsIPAddress()) {
    IPAddressNumber host_addr;
    if (!ParseIPLiteralToNumber(hostname.substr(host_info.out_host.begin,
                                                host_info.out_host.len),
                                &host_addr)) {
      return false;
    }
    switch (host_info.family) {
      case url::CanonHostInfo::IPV4:
      case url::CanonHostInfo::IPV6:
        return IsIPAddressReserved(host_addr);
      case url::CanonHostInfo::NEUTRAL:
      case url::CanonHostInfo::BROKEN:
        return false;
    }
  }

  // Check for a registry controlled portion of |hostname|, ignoring private
  // registries, as they already chain to ICANN-administered registries,
  // and explicitly ignoring unknown registries.
  //
  // Note: This means that as new gTLDs are introduced on the Internet, they
  // will be treated as non-unique until the registry controlled domain list
  // is updated. However, because gTLDs are expected to provide significant
  // advance notice to deprecate older versions of this code, this an
  // acceptable tradeoff.
  return 0 == registry_controlled_domains::GetRegistryLength(
                  canonical_name,
                  registry_controlled_domains::EXCLUDE_UNKNOWN_REGISTRIES,
                  registry_controlled_domains::EXCLUDE_PRIVATE_REGISTRIES);
}
#endif

SockaddrStorage::SockaddrStorage(const SockaddrStorage& other)
    : addr_len(other.addr_len),
      addr(reinterpret_cast<struct sockaddr*>(&addr_storage)) {
  memcpy(addr, other.addr, addr_len);
}

void SockaddrStorage::operator=(const SockaddrStorage& other) {
  addr_len = other.addr_len;
  // addr is already set to &this->addr_storage by default ctor.
  memcpy(addr, other.addr, addr_len);
}

// Extracts the address and port portions of a sockaddr.
bool GetIPAddressFromSockAddr(const struct sockaddr* sock_addr,
                              socklen_t sock_addr_len,
                              const uint8_t** address,
                              size_t* address_len,
                              uint16_t* port) {
  if (sock_addr->sa_family == AF_INET) {
    if (sock_addr_len < static_cast<socklen_t>(sizeof(struct sockaddr_in)))
      return false;
    const struct sockaddr_in* addr =
        reinterpret_cast<const struct sockaddr_in*>(sock_addr);
    *address = reinterpret_cast<const uint8_t*>(&addr->sin_addr);
    *address_len = kIPv4AddressSize;
    if (port)
      *port = base::NetToHost16(addr->sin_port);
    return true;
  }

  if (sock_addr->sa_family == AF_INET6) {
    if (sock_addr_len < static_cast<socklen_t>(sizeof(struct sockaddr_in6)))
      return false;
    const struct sockaddr_in6* addr =
        reinterpret_cast<const struct sockaddr_in6*>(sock_addr);
    *address = reinterpret_cast<const uint8_t*>(&addr->sin6_addr);
    *address_len = kIPv6AddressSize;
    if (port)
      *port = base::NetToHost16(addr->sin6_port);
    return true;
  }

#if defined(OS_WIN)
  if (sock_addr->sa_family == AF_BTH) {
    if (sock_addr_len < static_cast<socklen_t>(sizeof(SOCKADDR_BTH)))
      return false;
    const SOCKADDR_BTH* addr =
        reinterpret_cast<const SOCKADDR_BTH*>(sock_addr);
    *address = reinterpret_cast<const uint8_t*>(&addr->btAddr);
    *address_len = kBluetoothAddressSize;
    if (port)
      *port = static_cast<uint16_t>(addr->port);
    return true;
  }
#endif

  return false;  // Unrecognized |sa_family|.
}

std::string NetAddressToString(const struct sockaddr* sa,
                               socklen_t sock_addr_len) {
  const uint8_t* address;
  size_t address_len;
  if (!GetIPAddressFromSockAddr(sa, sock_addr_len, &address,
                                &address_len, NULL)) {
    NOTREACHED();
    return std::string();
  }
  return IPAddressToString(address, address_len);
}

std::string NetAddressToStringWithPort(const struct sockaddr* sa,
                                       socklen_t sock_addr_len) {
  const uint8_t* address;
  size_t address_len;
  uint16_t port;
  if (!GetIPAddressFromSockAddr(sa, sock_addr_len, &address,
                                &address_len, &port)) {
    NOTREACHED();
    return std::string();
  }
  return IPAddressToStringWithPort(address, address_len, port);
}

std::string GetHostName() {
#if defined(OS_NACL)
  NOTIMPLEMENTED();
  return std::string();
#else  // defined(OS_NACL)
#if defined(OS_WIN)
  EnsureWinsockInit();
#endif

  // Host names are limited to 255 bytes.
  char buffer[256];
  int result = gethostname(buffer, sizeof(buffer));
  if (result != 0) {
    DVLOG(1) << "gethostname() failed with " << result;
    buffer[0] = '\0';
  }
  return std::string(buffer);
#endif  // !defined(OS_NACL)
}

#if 0
void GetIdentityFromURL(const GURL& url,
                        base::string16* username,
                        base::string16* password) {
  UnescapeRule::Type flags =
      UnescapeRule::SPACES | UnescapeRule::URL_SPECIAL_CHARS;
  *username = UnescapeAndDecodeUTF8URLComponent(url.username(), flags);
  *password = UnescapeAndDecodeUTF8URLComponent(url.password(), flags);
}
#endif

#if 0
std::string GetHostOrSpecFromURL(const GURL& url) {
  return url.has_host() ? TrimEndingDot(url.host_piece()) : url.spec();
}
#endif

#if 0
GURL SimplifyUrlForRequest(const GURL& url) {
  DCHECK(url.is_valid());
  GURL::Replacements replacements;
  replacements.ClearUsername();
  replacements.ClearPassword();
  replacements.ClearRef();
  return url.ReplaceComponents(replacements);
}
#endif

bool HaveOnlyLoopbackAddresses() {
#if defined(OS_ANDROID)
  return android::HaveOnlyLoopbackAddresses();
#elif defined(OS_NACL)
  NOTIMPLEMENTED();
  return false;
#elif defined(OS_POSIX)
  struct ifaddrs* interface_addr = NULL;
  int rv = getifaddrs(&interface_addr);
  if (rv != 0) {
    DVLOG(1) << "getifaddrs() failed with errno = " << errno;
    return false;
  }

  bool result = true;
  for (struct ifaddrs* interface = interface_addr;
       interface != NULL;
       interface = interface->ifa_next) {
    if (!(IFF_UP & interface->ifa_flags))
      continue;
    if (IFF_LOOPBACK & interface->ifa_flags)
      continue;
    const struct sockaddr* addr = interface->ifa_addr;
    if (!addr)
      continue;
    if (addr->sa_family == AF_INET6) {
      // Safe cast since this is AF_INET6.
      const struct sockaddr_in6* addr_in6 =
          reinterpret_cast<const struct sockaddr_in6*>(addr);
      const struct in6_addr* sin6_addr = &addr_in6->sin6_addr;
      if (IN6_IS_ADDR_LOOPBACK(sin6_addr) || IN6_IS_ADDR_LINKLOCAL(sin6_addr))
        continue;
    }
    if (addr->sa_family != AF_INET6 && addr->sa_family != AF_INET)
      continue;

    result = false;
    break;
  }
  freeifaddrs(interface_addr);
  return result;
#elif defined(OS_WIN)
  // TODO(wtc): implement with the GetAdaptersAddresses function.
  NOTIMPLEMENTED();
  return false;
#else
  NOTIMPLEMENTED();
  return false;
#endif  // defined(various platforms)
}

const uint16_t* GetPortFieldFromSockaddr(const struct sockaddr* address,
                                         socklen_t address_len) {
  if (address->sa_family == AF_INET) {
    DCHECK_LE(sizeof(sockaddr_in), static_cast<size_t>(address_len));
    const struct sockaddr_in* sockaddr =
        reinterpret_cast<const struct sockaddr_in*>(address);
    return &sockaddr->sin_port;
  } else if (address->sa_family == AF_INET6) {
    DCHECK_LE(sizeof(sockaddr_in6), static_cast<size_t>(address_len));
    const struct sockaddr_in6* sockaddr =
        reinterpret_cast<const struct sockaddr_in6*>(address);
    return &sockaddr->sin6_port;
  } else {
    NOTREACHED();
    return NULL;
  }
}

int GetPortFromSockaddr(const struct sockaddr* address, socklen_t address_len) {
  const uint16_t* port_field = GetPortFieldFromSockaddr(address, address_len);
  if (!port_field)
    return -1;
  return base::NetToHost16(*port_field);
}

#if 0
bool ResolveLocalHostname(base::StringPiece host,
                          uint16_t port,
                          AddressList* address_list) {
  static const unsigned char kLocalhostIPv4[] = {127, 0, 0, 1};
  static const unsigned char kLocalhostIPv6[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

  std::string normalized_host = NormalizeHostname(host);

  address_list->clear();

  bool is_local6 = IsLocal6Hostname(normalized_host);
  if (!is_local6 && !IsLocalHostname(normalized_host))
    return false;

  address_list->push_back(
      IPEndPoint(IPAddressNumber(kLocalhostIPv6,
                                 kLocalhostIPv6 + arraysize(kLocalhostIPv6)),
                 port));
  if (!is_local6) {
    address_list->push_back(
        IPEndPoint(IPAddressNumber(kLocalhostIPv4,
                                   kLocalhostIPv4 + arraysize(kLocalhostIPv4)),
                   port));
  }

  return true;
}
#endif

#if 0
bool IsLocalhost(base::StringPiece host) {
  std::string normalized_host = NormalizeHostname(host);
  if (IsLocalHostname(normalized_host) || IsLocal6Hostname(normalized_host))
    return true;

  IPAddressNumber ip_number;
  if (ParseIPLiteralToNumber(host, &ip_number)) {
    size_t size = ip_number.size();
    switch (size) {
      case kIPv4AddressSize: {
        IPAddressNumber localhost_prefix;
        localhost_prefix.push_back(127);
        for (int i = 0; i < 3; ++i) {
          localhost_prefix.push_back(0);
        }
        return IPNumberMatchesPrefix(ip_number, localhost_prefix, 8);
      }

      case kIPv6AddressSize: {
        struct in6_addr sin6_addr;
        memcpy(&sin6_addr, &ip_number[0], kIPv6AddressSize);
        return !!IN6_IS_ADDR_LOOPBACK(&sin6_addr);
      }

      default:
        NOTREACHED();
    }
  }

  return false;
}
#endif

bool HasGoogleHost(const GURL& url) {
  static const char* kGoogleHostSuffixes[] = {
      ".google.com",
      ".youtube.com",
      ".gmail.com",
      ".doubleclick.net",
      ".gstatic.com",
      ".googlevideo.com",
      ".googleusercontent.com",
      ".googlesyndication.com",
      ".google-analytics.com",
      ".googleadservices.com",
      ".googleapis.com",
      ".ytimg.com",
  };
  base::StringPiece host = url.host_piece();
  for (const char* suffix : kGoogleHostSuffixes) {
    // Here it's possible to get away with faster case-sensitive comparisons
    // because the list above is all lowercase, and a GURL's host name will
    // always be canonicalized to lowercase as well.
    if (base::EndsWith(host, suffix, base::CompareCase::SENSITIVE))
      return true;
  }
  return false;
}

}  // namespace net
