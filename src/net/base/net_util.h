// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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
#include "base/strings/string16.h"
#if 0
#include "base/strings/utf_offset_string_conversions.h"
#endif
#include "net/base/address_family.h"
#if 0
#include "net/base/escape.h"
#endif
#include "net/base/net_export.h"
#if 0
#include "net/base/network_change_notifier.h"
#endif
// TODO(eroman): Remove this header and require consumers to include it
//               directly.
#if 0
#include "net/base/network_interfaces.h"
#endif

class GURL;

namespace base {
class Time;
}

namespace url {
struct CanonHostInfo;
struct Parsed;
}

namespace net {

class AddressList;

// This is a "forward declaration" to avoid including ip_address_number.h
// Keep this in sync.
typedef std::vector<unsigned char> IPAddressNumber;

// Used by FormatUrl to specify handling of certain parts of the url.
typedef uint32_t FormatUrlType;
typedef uint32_t FormatUrlTypes;

#if defined(OS_WIN)
// Bluetooth address size. Windows Bluetooth is supported via winsock.
static const size_t kBluetoothAddressSize = 6;
#endif

// Nothing is ommitted.
NET_EXPORT extern const FormatUrlType kFormatUrlOmitNothing;

// If set, any username and password are removed.
NET_EXPORT extern const FormatUrlType kFormatUrlOmitUsernamePassword;

// If the scheme is 'http://', it's removed.
NET_EXPORT extern const FormatUrlType kFormatUrlOmitHTTP;

// Omits the path if it is just a slash and there is no query or ref.  This is
// meaningful for non-file "standard" URLs.
NET_EXPORT extern const FormatUrlType kFormatUrlOmitTrailingSlashOnBareHostname;

// Convenience for omitting all unecessary types.
NET_EXPORT extern const FormatUrlType kFormatUrlOmitAll;

// Splits an input of the form <host>[":"<port>] into its consitituent parts.
// Saves the result into |*host| and |*port|. If the input did not have
// the optional port, sets |*port| to -1.
// Returns true if the parsing was successful, false otherwise.
// The returned host is NOT canonicalized, and may be invalid.
//
// IPv6 literals must be specified in a bracketed form, for instance:
//   [::1]:90 and [::1]
//
// The resultant |*host| in both cases will be "::1" (not bracketed).
NET_EXPORT bool ParseHostAndPort(
    std::string::const_iterator host_and_port_begin,
    std::string::const_iterator host_and_port_end,
    std::string* host,
    int* port);
NET_EXPORT bool ParseHostAndPort(
    const std::string& host_and_port,
    std::string* host,
    int* port);

// Returns a host:port string for the given URL.
NET_EXPORT std::string GetHostAndPort(const GURL& url);

// Returns a host[:port] string for the given URL, where the port is omitted
// if it is the default for the URL's scheme.
NET_EXPORT_PRIVATE std::string GetHostAndOptionalPort(const GURL& url);

// Returns true if |hostname| contains a non-registerable or non-assignable
// domain name (eg: a gTLD that has not been assigned by IANA) or an IP address
// that falls in an IANA-reserved range.
NET_EXPORT bool IsHostnameNonUnique(const std::string& hostname);

// Convenience struct for when you need a |struct sockaddr|.
struct SockaddrStorage {
  SockaddrStorage() : addr_len(sizeof(addr_storage)),
                      addr(reinterpret_cast<struct sockaddr*>(&addr_storage)) {}
  SockaddrStorage(const SockaddrStorage& other);
  void operator=(const SockaddrStorage& other);

  struct sockaddr_storage addr_storage;
  socklen_t addr_len;
  struct sockaddr* const addr;
};

// Extracts the IP address and port portions of a sockaddr. |port| is optional,
// and will not be filled in if NULL.
bool GetIPAddressFromSockAddr(const struct sockaddr* sock_addr,
                              socklen_t sock_addr_len,
                              const unsigned char** address,
                              size_t* address_len,
                              uint16_t* port);

// Same as IPAddressToString() but for a sockaddr. This output will not include
// the IPv6 scope ID.
NET_EXPORT std::string NetAddressToString(const struct sockaddr* sa,
                                          socklen_t sock_addr_len);

// Same as IPAddressToStringWithPort() but for a sockaddr. This output will not
// include the IPv6 scope ID.
NET_EXPORT std::string NetAddressToStringWithPort(const struct sockaddr* sa,
                                                  socklen_t sock_addr_len);

// Returns the hostname of the current system. Returns empty string on failure.
NET_EXPORT std::string GetHostName();

// Extracts the unescaped username/password from |url|, saving the results
// into |*username| and |*password|.
NET_EXPORT_PRIVATE void GetIdentityFromURL(const GURL& url,
                                           base::string16* username,
                                           base::string16* password);

// Returns either the host from |url|, or, if the host is empty, the full spec.
NET_EXPORT std::string GetHostOrSpecFromURL(const GURL& url);

// Return the value of the HTTP response header with name 'name'.  'headers'
// should be in the format that URLRequest::GetResponseHeaders() returns.
// Returns the empty string if the header is not found.
NET_EXPORT std::string GetSpecificHeader(const std::string& headers,
                                         const std::string& name);

// Converts the given host name to unicode characters. This can be called for
// any host name, if the input is not IDN or is invalid in some way, we'll just
// return the ASCII source so it is still usable.
//
// The input should be the canonicalized ASCII host name from GURL. This
// function does NOT accept UTF-8!
//
// |languages| is a comma separated list of ISO 639 language codes. It
// is used to determine whether a hostname is 'comprehensible' to a user
// who understands languages listed. |host| will be converted to a
// human-readable form (Unicode) ONLY when each component of |host| is
// regarded as 'comprehensible'. Scipt-mixing is not allowed except that
// Latin letters in the ASCII range can be mixed with a limited set of
// script-language pairs (currently Han, Kana and Hangul for zh,ja and ko).
// When |languages| is empty, even that mixing is not allowed.
NET_EXPORT base::string16 IDNToUnicode(const std::string& host,
                                       const std::string& languages);

// Canonicalizes |host| and returns it.  Also fills |host_info| with
// IP address information.  |host_info| must not be NULL.
NET_EXPORT std::string CanonicalizeHost(const std::string& host,
                                        url::CanonHostInfo* host_info);

// Returns true if |host| is not an IP address and is compliant with a set of
// rules based on RFC 1738 and tweaked to be compatible with the real world.
// The rules are:
//   * One or more components separated by '.'
//   * Each component contains only alphanumeric characters and '-' or '_'
//   * The last component begins with an alphanumeric character
//   * Optional trailing dot after last component (means "treat as FQDN")
//
// NOTE: You should only pass in hosts that have been returned from
// CanonicalizeHost(), or you may not get accurate results.
NET_EXPORT bool IsCanonicalizedHostCompliant(const std::string& host);

// Call these functions to get the html snippet for a directory listing.
// The return values of both functions are in UTF-8.
NET_EXPORT std::string GetDirectoryListingHeader(const base::string16& title);

// Given the name of a file in a directory (ftp or local) and
// other information (is_dir, size, modification time), it returns
// the html snippet to add the entry for the file to the directory listing.
// Currently, it's a script tag containing a call to a Javascript function
// |addRow|.
//
// |name| is the file name to be displayed. |raw_bytes| will be used
// as the actual target of the link (so for example, ftp links should use
// server's encoding). If |raw_bytes| is an empty string, UTF-8 encoded |name|
// will be used.
//
// Both |name| and |raw_bytes| are escaped internally.
NET_EXPORT std::string GetDirectoryListingEntry(const base::string16& name,
                                                const std::string& raw_bytes,
                                                bool is_dir,
                                                int64_t size,
                                                base::Time modified);

// If text starts with "www." it is removed, otherwise text is returned
// unmodified.
NET_EXPORT base::string16 StripWWW(const base::string16& text);

// Runs |url|'s host through StripWWW().  |url| must be valid.
NET_EXPORT base::string16 StripWWWFromHost(const GURL& url);

// Checks if |port| is in the valid range (0 to 65535, though 0 is technically
// reserved).  Should be used before casting a port to a uint16_t.
NET_EXPORT bool IsPortValid(int port);

// Returns true if the port is in the range [0, 1023]. These ports are
// registered by IANA and typically need root access to listen on.
bool IsWellKnownPort(int port);

// Checks if the port is allowed for the specified scheme.  Ports set as allowed
// with SetExplicitlyAllowedPorts() or by using ScopedPortException() will be
// considered allowed for any scheme.
NET_EXPORT bool IsPortAllowedForScheme(int port, const std::string& url_scheme);

// Returns the number of explicitly allowed ports; for testing.
NET_EXPORT_PRIVATE size_t GetCountOfExplicitlyAllowedPorts();

NET_EXPORT void SetExplicitlyAllowedPorts(const std::string& allowed_ports);

class NET_EXPORT ScopedPortException {
 public:
  explicit ScopedPortException(int port);
  ~ScopedPortException();

 private:
  int port_;

  DISALLOW_COPY_AND_ASSIGN(ScopedPortException);
};

// Set socket to non-blocking mode
NET_EXPORT int SetNonBlocking(int fd);

// Formats the host in |url| and appends it to |output|.  The host formatter
// takes the same accept languages component as ElideURL().
NET_EXPORT void AppendFormattedHost(const GURL& url,
                                    const std::string& languages,
                                    base::string16* output);

// Creates a string representation of |url|. The IDN host name may be in Unicode
// if |languages| accepts the Unicode representation. |format_type| is a bitmask
// of FormatUrlTypes, see it for details. |unescape_rules| defines how to clean
// the URL for human readability. You will generally want |UnescapeRule::SPACES|
// for display to the user if you can handle spaces, or |UnescapeRule::NORMAL|
// if not. If the path part and the query part seem to be encoded in %-encoded
// UTF-8, decodes %-encoding and UTF-8.
//
// The last three parameters may be NULL.
//
// |new_parsed| will be set to the parsing parameters of the resultant URL.
//
// |prefix_end| will be the length before the hostname of the resultant URL.
//
// |offset[s]_for_adjustment| specifies one or more offsets into the original
// URL, representing insertion or selection points between characters: if the
// input is "http://foo.com/", offset 0 is before the entire URL, offset 7 is
// between the scheme and the host, and offset 15 is after the end of the URL.
// Valid input offsets range from 0 to the length of the input URL string.  On
// exit, each offset will have been modified to reflect any changes made to the
// output string.  For example, if |url| is "http://a:b@c.com/",
// |omit_username_password| is true, and an offset is 12 (pointing between 'c'
// and '.'), then on return the output string will be "http://c.com/" and the
// offset will be 8.  If an offset cannot be successfully adjusted (e.g. because
// it points into the middle of a component that was entirely removed or into
// the middle of an encoding sequence), it will be set to base::string16::npos.
// For consistency, if an input offset points between the scheme and the
// username/password, and both are removed, on output this offset will be 0
// rather than npos; this means that offsets at the starts and ends of removed
// components are always transformed the same way regardless of what other
// components are adjacent.
#if 0
NET_EXPORT base::string16 FormatUrl(const GURL& url,
                                    const std::string& languages,
                                    FormatUrlTypes format_types,
                                    UnescapeRule::Type unescape_rules,
                                    url::Parsed* new_parsed,
                                    size_t* prefix_end,
                                    size_t* offset_for_adjustment);
NET_EXPORT base::string16 FormatUrlWithOffsets(
    const GURL& url,
    const std::string& languages,
    FormatUrlTypes format_types,
    UnescapeRule::Type unescape_rules,
    url::Parsed* new_parsed,
    size_t* prefix_end,
    std::vector<size_t>* offsets_for_adjustment);
// This function is like those above except it takes |adjustments| rather
// than |offset[s]_for_adjustment|.  |adjustments| will be set to reflect all
// the transformations that happened to |url| to convert it into the returned
// value.
NET_EXPORT base::string16 FormatUrlWithAdjustments(
    const GURL& url,
    const std::string& languages,
    FormatUrlTypes format_types,
    UnescapeRule::Type unescape_rules,
    url::Parsed* new_parsed,
    size_t* prefix_end,
    base::OffsetAdjuster::Adjustments* adjustments);

// This is a convenience function for FormatUrl() with
// format_types = kFormatUrlOmitAll and unescape = SPACES.  This is the typical
// set of flags for "URLs to display to the user".  You should be cautious about
// using this for URLs which will be parsed or sent to other applications.
inline base::string16 FormatUrl(const GURL& url, const std::string& languages) {
  return FormatUrl(url, languages, kFormatUrlOmitAll, UnescapeRule::SPACES,
                   NULL, NULL, NULL);
}

// Returns whether FormatUrl() would strip a trailing slash from |url|, given a
// format flag including kFormatUrlOmitTrailingSlashOnBareHostname.
NET_EXPORT bool CanStripTrailingSlash(const GURL& url);
#endif

// Strip the portions of |url| that aren't core to the network request.
//   - user name / password
//   - reference section
NET_EXPORT_PRIVATE GURL SimplifyUrlForRequest(const GURL& url);

// Returns true if it can determine that only loopback addresses are configured.
// i.e. if only 127.0.0.1 and ::1 are routable.
// Also returns false if it cannot determine this.
bool HaveOnlyLoopbackAddresses();

// Returns AddressFamily of the address.
NET_EXPORT_PRIVATE AddressFamily GetAddressFamily(
    const IPAddressNumber& address);

// Maps the given AddressFamily to either AF_INET, AF_INET6 or AF_UNSPEC.
NET_EXPORT_PRIVATE int ConvertAddressFamily(AddressFamily address_family);

// Retuns the port field of the |sockaddr|.
const uint16_t* GetPortFieldFromSockaddr(const struct sockaddr* address,
                                         socklen_t address_len);
// Returns the value of port in |sockaddr| (in host byte ordering).
NET_EXPORT_PRIVATE int GetPortFromSockaddr(const struct sockaddr* address,
                                           socklen_t address_len);

// Resolves a local hostname (such as "localhost" or "localhost6") into
// IP endpoints with the given port. Returns true if |host| is a local
// hostname and false otherwise. Special IPv6 names (e.g. "localhost6")
// will resolve to an IPv6 address only, whereas other names will
// resolve to both IPv4 and IPv6.
NET_EXPORT_PRIVATE bool ResolveLocalHostname(const std::string& host,
                                             uint16_t port,
                                             AddressList* address_list);

// Returns true if |host| is one of the local hostnames
// (e.g. "localhost") or IP addresses (IPv4 127.0.0.0/8 or IPv6 ::1).
//
// Note that this function does not check for IP addresses other than
// the above, although other IP addresses may point to the local
// machine.
NET_EXPORT_PRIVATE bool IsLocalhost(const std::string& host);

NET_EXPORT_PRIVATE bool IsLocalhostTLD(const std::string& host);

// Returns true if the url's host is a Google server. This should only be used
// for histograms and shouldn't be used to affect behavior.
NET_EXPORT_PRIVATE bool HasGoogleHost(const GURL& url);

// A subset of IP address attributes which are actionable by the
// application layer. Currently unimplemented for all hosts;
// IP_ADDRESS_ATTRIBUTE_NONE is always returned.
enum IPAddressAttributes {
  IP_ADDRESS_ATTRIBUTE_NONE = 0,

  // A temporary address is dynamic by nature and will not contain MAC
  // address. Presence of MAC address in IPv6 addresses can be used to
  // track an endpoint and cause privacy concern. Please refer to
  // RFC4941.
  IP_ADDRESS_ATTRIBUTE_TEMPORARY = 1 << 0,

  // A temporary address could become deprecated once the preferred
  // lifetime is reached. It is still valid but shouldn't be used to
  // create new connections.
  IP_ADDRESS_ATTRIBUTE_DEPRECATED = 1 << 1,
};

// Differentiated Services Code Point.
// See http://tools.ietf.org/html/rfc2474 for details.
enum DiffServCodePoint {
  DSCP_NO_CHANGE = -1,
  DSCP_FIRST = DSCP_NO_CHANGE,
  DSCP_DEFAULT = 0,  // Same as DSCP_CS0
  DSCP_CS0  = 0,   // The default
  DSCP_CS1  = 8,   // Bulk/background traffic
  DSCP_AF11 = 10,
  DSCP_AF12 = 12,
  DSCP_AF13 = 14,
  DSCP_CS2  = 16,
  DSCP_AF21 = 18,
  DSCP_AF22 = 20,
  DSCP_AF23 = 22,
  DSCP_CS3  = 24,
  DSCP_AF31 = 26,
  DSCP_AF32 = 28,
  DSCP_AF33 = 30,
  DSCP_CS4  = 32,
  DSCP_AF41 = 34,  // Video
  DSCP_AF42 = 36,  // Video
  DSCP_AF43 = 38,  // Video
  DSCP_CS5  = 40,  // Video
  DSCP_EF   = 46,  // Voice
  DSCP_CS6  = 48,  // Voice
  DSCP_CS7  = 56,  // Control messages
  DSCP_LAST = DSCP_CS7
};

}  // namespace net

#endif  // NET_BASE_NET_UTIL_H_
