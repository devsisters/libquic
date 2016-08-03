#include <boringssl/bssl.h>
/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <vector>

#include <assert.h>
#include <string.h>

#include <boringssl/crypto.h>
#include <boringssl/digest.h>
#include <boringssl/err.h>
#include <boringssl/evp.h>
#include <boringssl/pem.h>
#include <boringssl/x509.h>

#include "../test/scoped_types.h"


static const char kCrossSigningRootPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICcTCCAdqgAwIBAgIIagJHiPvE0MowDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwo3qFvSB9Zmlbpzn9wJp\n"
"ikI75Rxkatez8VkLqyxbOhPYl2Haz8F5p1gDG96dCI6jcLGgu3AKT9uhEQyyUko5\n"
"EKYasazSeA9CQrdyhPg0mkTYVETnPM1W/ebid1YtqQbq1CMWlq2aTDoSGAReGFKP\n"
"RTdXAbuAXzpCfi/d8LqV13UCAwEAAaN6MHgwDgYDVR0PAQH/BAQDAgIEMB0GA1Ud\n"
"JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MBkGA1Ud\n"
"DgQSBBBHKHC7V3Z/3oLvEZx0RZRwMBsGA1UdIwQUMBKAEEcocLtXdn/egu8RnHRF\n"
"lHAwDQYJKoZIhvcNAQELBQADgYEAnglibsy6mGtpIXivtlcz4zIEnHw/lNW+r/eC\n"
"CY7evZTmOoOuC/x9SS3MF9vawt1HFUummWM6ZgErqVBOXIB4//ykrcCgf5ZbF5Hr\n"
"+3EFprKhBqYiXdD8hpBkrBoXwn85LPYWNd2TceCrx0YtLIprE2R5MB2RIq8y4Jk3\n"
"YFXvkME=\n"
"-----END CERTIFICATE-----\n";

static const char kRootCAPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICVTCCAb6gAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwLjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwIBcNMTUwMTAx\n"
"MDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMC4xGjAYBgNVBAoTEUJvcmluZ1NTTCBU\n"
"RVNUSU5HMRAwDgYDVQQDEwdSb290IENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
"iQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM\n"
"2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw+QzGj+mz36NqhGxDWb6dstB2m8PX+plZ\n"
"w7jl81MDvUnWs8yiQ/6twgu5AbhWKZQDJKcNKCEpqa6UW0r5nwIDAQABo3oweDAO\n"
"BgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8G\n"
"A1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEEA31wH7QC+4HH5UBCeMWQEwGwYDVR0j\n"
"BBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOBgQDXylEK77Za\n"
"kKeY6ZerrScWyZhrjIGtHFu09qVpdJEzrk87k2G7iHHR9CAvSofCgEExKtWNS9dN\n"
"+9WiZp/U48iHLk7qaYXdEuO07No4BYtXn+lkOykE+FUxmA4wvOF1cTd2tdj3MzX2\n"
"kfGIBAYhzGZWhY3JbhIfTEfY1PNM1pWChQ==\n"
"-----END CERTIFICATE-----\n";

static const char kRootCrossSignedPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICYzCCAcygAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
"dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowLjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwgZ8wDQYJKoZI\n"
"hvcNAQEBBQADgY0AMIGJAoGBAOkOfxEM5lrmhoNw9lEHLgJ4EfWyJJI47iZiAseU\n"
"8T6hd2rAj9UiaLZd4kza4IURNcKSckmNgbSIl2u3/LJEW9lNBnD5DMaP6bPfo2qE\n"
"bENZvp2y0Habw9f6mVnDuOXzUwO9SdazzKJD/q3CC7kBuFYplAMkpw0oISmprpRb\n"
"SvmfAgMBAAGjejB4MA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEFBQcD\n"
"AQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQQDfXAftAL7gc\n"
"flQEJ4xZATAbBgNVHSMEFDASgBBHKHC7V3Z/3oLvEZx0RZRwMA0GCSqGSIb3DQEB\n"
"CwUAA4GBAErTxYJ0en9HVRHAAr5OO5wuk5Iq3VMc79TMyQLCXVL8YH8Uk7KEwv+q\n"
"9MEKZv2eR/Vfm4HlXlUuIqfgUXbwrAYC/YVVX86Wnbpy/jc73NYVCq8FEZeO+0XU\n"
"90SWAPDdp+iL7aZdimnMtG1qlM1edmz8AKbrhN/R3IbA2CL0nCWV\n"
"-----END CERTIFICATE-----\n";

static const char kIntermediatePEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICXjCCAcegAwIBAgIJAKJMH+7rscPcMA0GCSqGSIb3DQEBCwUAMC4xGjAYBgNV\n"
"BAoTEUJvcmluZ1NTTCBURVNUSU5HMRAwDgYDVQQDEwdSb290IENBMCAXDTE1MDEw\n"
"MTAwMDAwMFoYDzIxMDAwMTAxMDAwMDAwWjA2MRowGAYDVQQKExFCb3JpbmdTU0wg\n"
"VEVTVElORzEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIGfMA0GCSqGSIb3DQEB\n"
"AQUAA4GNADCBiQKBgQC7YtI0l8ocTYJ0gKyXTtPL4iMJCNY4OcxXl48jkncVG1Hl\n"
"blicgNUa1r9m9YFtVkxvBinb8dXiUpEGhVg4awRPDcatlsBSEBuJkiZGYbRcAmSu\n"
"CmZYnf6u3aYQ18SU8WqVERPpE4cwVVs+6kwlzRw0+XDoZAczu8ZezVhCUc6NbQID\n"
"AQABo3oweDAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG\n"
"AQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEIwaaKi1dttdV3sfjRSy\n"
"BqMwGwYDVR0jBBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOB\n"
"gQCvnolNWEHuQS8PFVVyuLR+FKBeUUdrVbSfHSzTqNAqQGp0C9fk5oCzDq6ZgTfY\n"
"ESXM4cJhb3IAnW0UM0NFsYSKQJ50JZL2L3z5ZLQhHdbs4RmODGoC40BVdnJ4/qgB\n"
"aGSh09eQRvAVmbVCviDK2ipkWNegdyI19jFfNP5uIkGlYg==\n"
"-----END CERTIFICATE-----\n";

static const char kIntermediateSelfSignedPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICZjCCAc+gAwIBAgIJAKJMH+7rscPcMA0GCSqGSIb3DQEBCwUAMDYxGjAYBgNV\n"
"BAoTEUJvcmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0Ew\n"
"IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDYxGjAYBgNVBAoTEUJv\n"
"cmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0EwgZ8wDQYJ\n"
"KoZIhvcNAQEBBQADgY0AMIGJAoGBALti0jSXyhxNgnSArJdO08viIwkI1jg5zFeX\n"
"jyOSdxUbUeVuWJyA1RrWv2b1gW1WTG8GKdvx1eJSkQaFWDhrBE8Nxq2WwFIQG4mS\n"
"JkZhtFwCZK4KZlid/q7dphDXxJTxapURE+kThzBVWz7qTCXNHDT5cOhkBzO7xl7N\n"
"WEJRzo1tAgMBAAGjejB4MA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEF\n"
"BQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQjBpoqLV2\n"
"211Xex+NFLIGozAbBgNVHSMEFDASgBCMGmiotXbbXVd7H40UsgajMA0GCSqGSIb3\n"
"DQEBCwUAA4GBALcccSrAQ0/EqQBsx0ZDTUydHXXNP2DrUkpUKmAXIe8McqIVSlkT\n"
"6H4xz7z8VRKBo9j+drjjtCw2i0CQc8aOLxRb5WJ8eVLnaW2XRlUqAzhF0CrulfVI\n"
"E4Vs6ZLU+fra1WAuIj6qFiigRja+3YkZArG8tMA9vtlhTX/g7YBZIkqH\n"
"-----END CERTIFICATE-----\n";

static const char kLeafPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICXjCCAcegAwIBAgIIWjO48ufpunYwDQYJKoZIhvcNAQELBQAwNjEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAg\n"
"Fw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowMjEaMBgGA1UEChMRQm9y\n"
"aW5nU1NMIFRFU1RJTkcxFDASBgNVBAMTC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3\n"
"DQEBAQUAA4GNADCBiQKBgQDD0U0ZYgqShJ7oOjsyNKyVXEHqeafmk/bAoPqY/h1c\n"
"oPw2E8KmeqiUSoTPjG5IXSblOxcqpbAXgnjPzo8DI3GNMhAf8SYNYsoH7gc7Uy7j\n"
"5x8bUrisGnuTHqkqH6d4/e7ETJ7i3CpR8bvK16DggEvQTudLipz8FBHtYhFakfdh\n"
"TwIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"
"CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEKN5pvbur7mlXjeMEYA0\n"
"4nUwGwYDVR0jBBQwEoAQjBpoqLV2211Xex+NFLIGozANBgkqhkiG9w0BAQsFAAOB\n"
"gQBj/p+JChp//LnXWC1k121LM/ii7hFzQzMrt70bny406SGz9jAjaPOX4S3gt38y\n"
"rhjpPukBlSzgQXFg66y6q5qp1nQTD1Cw6NkKBe9WuBlY3iYfmsf7WT8nhlT1CttU\n"
"xNCwyMX9mtdXdQicOfNjIGUCD5OLV5PgHFPRKiHHioBAhg==\n"
"-----END CERTIFICATE-----\n";

static const char kLeafNoKeyUsagePEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICNTCCAZ6gAwIBAgIJAIFQGaLQ0G2mMA0GCSqGSIb3DQEBCwUAMDYxGjAYBgNV\n"
"BAoTEUJvcmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0Ew\n"
"IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDcxGjAYBgNVBAoTEUJv\n"
"cmluZ1NTTCBURVNUSU5HMRkwFwYDVQQDExBldmlsLmV4YW1wbGUuY29tMIGfMA0G\n"
"CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOKoZe75NPz77EOaMMl4/0s3PyQw++zJvp\n"
"ejHAxZiTPCJgMbEHLrSzNoHdopg+CLUH5bE4wTXM8w9Inv5P8OAFJt7gJuPUunmk\n"
"j+NoU3QfzOR6BroePcz1vXX9jyVHRs087M/sLqWRHu9IR+/A+UTcBaWaFiDVUxtJ\n"
"YOwFMwjNPQIDAQABo0gwRjAMBgNVHRMBAf8EAjAAMBkGA1UdDgQSBBBJfLEUWHq1\n"
"27rZ1AVx2J5GMBsGA1UdIwQUMBKAEIwaaKi1dttdV3sfjRSyBqMwDQYJKoZIhvcN\n"
"AQELBQADgYEALVKN2Y3LZJOtu6SxFIYKxbLaXhTGTdIjxipZhmbBRDFjbZjZZOTe\n"
"6Oo+VDNPYco4rBexK7umYXJyfTqoY0E8dbiImhTcGTEj7OAB3DbBomgU1AYe+t2D\n"
"uwBqh4Y3Eto+Zn4pMVsxGEfUpjzjZDel7bN1/oU/9KWPpDfywfUmjgk=\n"
"-----END CERTIFICATE-----\n";

static const char kForgeryPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICZzCCAdCgAwIBAgIIdTlMzQoKkeMwDQYJKoZIhvcNAQELBQAwNzEaMBgGA1UE\n"
"ChMRQm9yaW5nU1NMIFRFU1RJTkcxGTAXBgNVBAMTEGV2aWwuZXhhbXBsZS5jb20w\n"
"IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDoxGjAYBgNVBAoTEUJv\n"
"cmluZ1NTTCBURVNUSU5HMRwwGgYDVQQDExNmb3JnZXJ5LmV4YW1wbGUuY29tMIGf\n"
"MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDADTwruBQZGb7Ay6s9HiYv5d1lwtEy\n"
"xQdA2Sy8Rn8uA20Q4KgqwVY7wzIZ+z5Butrsmwb70gdG1XU+yRaDeE7XVoW6jSpm\n"
"0sw35/5vJbTcL4THEFbnX0OPZnvpuZDFUkvVtq5kxpDWsVyM24G8EEq7kPih3Sa3\n"
"OMhXVXF8kso6UQIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI\n"
"KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEEYJ/WHM\n"
"8p64erPWIg4/liwwGwYDVR0jBBQwEoAQSXyxFFh6tdu62dQFcdieRjANBgkqhkiG\n"
"9w0BAQsFAAOBgQA+zH7bHPElWRWJvjxDqRexmYLn+D3Aivs8XgXQJsM94W0EzSUf\n"
"DSLfRgaQwcb2gg2xpDFoG+W0vc6O651uF23WGt5JaFFJJxqjII05IexfCNhuPmp4\n"
"4UZAXPttuJXpn74IY1tuouaM06B3vXKZR+/ityKmfJvSwxacmFcK+2ziAg==\n"
"-----END CERTIFICATE-----\n";

// kExamplePSSCert is an example RSA-PSS self-signed certificate, signed with
// the default hash functions.
static const char kExamplePSSCert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIICYjCCAcagAwIBAgIJAI3qUyT6SIfzMBIGCSqGSIb3DQEBCjAFogMCAWowRTEL\n"
"MAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVy\n"
"bmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xNDEwMDkxOTA5NTVaFw0xNTEwMDkxOTA5\n"
"NTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\n"
"DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZ8wDQYJKoZIhvcNAQEBBQADgY0A\n"
"MIGJAoGBAPi4bIO0vNmoV8CltFl2jFQdeesiUgR+0zfrQf2D+fCmhRU0dXFahKg8\n"
"0u9aTtPel4rd/7vPCqqGkr64UOTNb4AzMHYTj8p73OxaymPHAyXvqIqDWHYg+hZ3\n"
"13mSYwFIGth7Z/FSVUlO1m5KXNd6NzYM3t2PROjCpywrta9kS2EHAgMBAAGjUDBO\n"
"MB0GA1UdDgQWBBTQQfuJQR6nrVrsNF1JEflVgXgfEzAfBgNVHSMEGDAWgBTQQfuJ\n"
"QR6nrVrsNF1JEflVgXgfEzAMBgNVHRMEBTADAQH/MBIGCSqGSIb3DQEBCjAFogMC\n"
"AWoDgYEASUy2RZcgNbNQZA0/7F+V1YTLEXwD16bm+iSVnzGwtexmQVEYIZG74K/w\n"
"xbdZQdTbpNJkp1QPjPfh0zsatw6dmt5QoZ8K8No0DjR9dgf+Wvv5WJvJUIQBoAVN\n"
"Z0IL+OQFz6+LcTHxD27JJCebrATXZA0wThGTQDm7crL+a+SujBY=\n"
"-----END CERTIFICATE-----\n";

// kBadPSSCertPEM is a self-signed RSA-PSS certificate with bad parameters.
static const char kBadPSSCertPEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDdjCCAjqgAwIBAgIJANcwZLyfEv7DMD4GCSqGSIb3DQEBCjAxoA0wCwYJYIZI\n"
"AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIEAgIA3jAnMSUwIwYD\n"
"VQQDDBxUZXN0IEludmFsaWQgUFNTIGNlcnRpZmljYXRlMB4XDTE1MTEwNDE2MDIz\n"
"NVoXDTE1MTIwNDE2MDIzNVowJzElMCMGA1UEAwwcVGVzdCBJbnZhbGlkIFBTUyBj\n"
"ZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTaM7WH\n"
"qVCAGAIA+zL1KWvvASTrhlq+1ePdO7wsrWX2KiYoTYrJYTnxhLnn0wrHqApt79nL\n"
"IBG7cfShyZqFHOY/IzlYPMVt+gPo293gw96Fds5JBsjhjkyGnOyr9OUntFqvxDbT\n"
"IIFU7o9IdxD4edaqjRv+fegVE+B79pDk4s0ujsk6dULtCg9Rst0ucGFo19mr+b7k\n"
"dbfn8pZ72ZNDJPueVdrUAWw9oll61UcYfk75XdrLk6JlL41GrYHc8KlfXf43gGQq\n"
"QfrpHkg4Ih2cI6Wt2nhFGAzrlcorzLliQIUJRIhM8h4IgDfpBpaPdVQLqS2pFbXa\n"
"5eQjqiyJwak2vJ8CAwEAAaNQME4wHQYDVR0OBBYEFCt180N4oGUt5LbzBwQ4Ia+2\n"
"4V97MB8GA1UdIwQYMBaAFCt180N4oGUt5LbzBwQ4Ia+24V97MAwGA1UdEwQFMAMB\n"
"Af8wMQYJKoZIhvcNAQEKMCSgDTALBglghkgBZQMEAgGhDTALBgkqhkiG9w0BAQii\n"
"BAICAN4DggEBAAjBtm90lGxgddjc4Xu/nbXXFHVs2zVcHv/mqOZoQkGB9r/BVgLb\n"
"xhHrFZ2pHGElbUYPfifdS9ztB73e1d4J+P29o0yBqfd4/wGAc/JA8qgn6AAEO/Xn\n"
"plhFeTRJQtLZVl75CkHXgUGUd3h+ADvKtcBuW9dSUncaUrgNKR8u/h/2sMG38RWY\n"
"DzBddC/66YTa3r7KkVUfW7yqRQfELiGKdcm+bjlTEMsvS+EhHup9CzbpoCx2Fx9p\n"
"NPtFY3yEObQhmL1JyoCRWqBE75GzFPbRaiux5UpEkns+i3trkGssZzsOuVqHNTNZ\n"
"lC9+9hPHIoc9UMmAQNo1vGIW3NWVoeGbaJ8=\n"
"-----END CERTIFICATE-----\n";

static const char kRSAKey[] =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXgIBAAKBgQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92\n"
"kWdGMdAQhLciHnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiF\n"
"KKAnHmUcrgfVW28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQAB\n"
"AoGBAIBy09Fd4DOq/Ijp8HeKuCMKTHqTW1xGHshLQ6jwVV2vWZIn9aIgmDsvkjCe\n"
"i6ssZvnbjVcwzSoByhjN8ZCf/i15HECWDFFh6gt0P5z0MnChwzZmvatV/FXCT0j+\n"
"WmGNB/gkehKjGXLLcjTb6dRYVJSCZhVuOLLcbWIV10gggJQBAkEA8S8sGe4ezyyZ\n"
"m4e9r95g6s43kPqtj5rewTsUxt+2n4eVodD+ZUlCULWVNAFLkYRTBCASlSrm9Xhj\n"
"QpmWAHJUkQJBAOVzQdFUaewLtdOJoPCtpYoY1zd22eae8TQEmpGOR11L6kbxLQsk\n"
"aMly/DOnOaa82tqAGTdqDEZgSNmCeKKknmECQAvpnY8GUOVAubGR6c+W90iBuQLj\n"
"LtFp/9ihd2w/PoDwrHZaoUYVcT4VSfJQog/k7kjE4MYXYWL8eEKg3WTWQNECQQDk\n"
"104Wi91Umd1PzF0ijd2jXOERJU1wEKe6XLkYYNHWQAe5l4J4MWj9OdxFXAxIuuR/\n"
"tfDwbqkta4xcux67//khAkEAvvRXLHTaa6VFzTaiiO8SaFsHV3lQyXOtMrBpB5jd\n"
"moZWgjHvB2W9Ckn7sDqsPB+U2tyX0joDdQEyuiMECDY8oQ==\n"
"-----END RSA PRIVATE KEY-----\n";


// CertFromPEM parses the given, NUL-terminated pem block and returns an
// |X509*|.
static ScopedX509 CertFromPEM(const char *pem) {
  ScopedBIO bio(BIO_new_mem_buf(pem, strlen(pem)));
  return ScopedX509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// PrivateKeyFromPEM parses the given, NUL-terminated pem block and returns an
// |EVP_PKEY*|.
static ScopedEVP_PKEY PrivateKeyFromPEM(const char *pem) {
  ScopedBIO bio(BIO_new_mem_buf(const_cast<char *>(pem), strlen(pem)));
  return ScopedEVP_PKEY(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// CertsToStack converts a vector of |X509*| to an OpenSSL STACK_OF(X509*),
// bumping the reference counts for each certificate in question.
static STACK_OF(X509)* CertsToStack(const std::vector<X509*> &certs) {
  ScopedX509Stack stack(sk_X509_new_null());
  if (!stack) {
    return nullptr;
  }
  for (auto cert : certs) {
    if (!sk_X509_push(stack.get(), cert)) {
      return nullptr;
    }
    X509_up_ref(cert);
  }

  return stack.release();
}

static bool Verify(X509 *leaf, const std::vector<X509 *> &roots,
                   const std::vector<X509 *> &intermediates,
                   unsigned long flags = 0) {
  ScopedX509Stack roots_stack(CertsToStack(roots));
  ScopedX509Stack intermediates_stack(CertsToStack(intermediates));
  if (!roots_stack ||
      !intermediates_stack) {
    return false;
  }

  ScopedX509_STORE_CTX ctx(X509_STORE_CTX_new());
  if (!ctx) {
    return false;
  }
  if (!X509_STORE_CTX_init(ctx.get(), nullptr /* no X509_STORE */, leaf,
                           intermediates_stack.get())) {
    return false;
  }

  X509_STORE_CTX_trusted_stack(ctx.get(), roots_stack.get());

  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  if (param == nullptr) {
    return false;
  }
  X509_VERIFY_PARAM_set_time(param, 1452807555 /* Jan 14th, 2016 */);
  X509_VERIFY_PARAM_set_depth(param, 16);
  if (flags) {
    X509_VERIFY_PARAM_set_flags(param, flags);
  }
  X509_STORE_CTX_set0_param(ctx.get(), param);

  ERR_clear_error();
  return X509_verify_cert(ctx.get()) == 1;
}

static bool TestVerify() {
  ScopedX509 cross_signing_root(CertFromPEM(kCrossSigningRootPEM));
  ScopedX509 root(CertFromPEM(kRootCAPEM));
  ScopedX509 root_cross_signed(CertFromPEM(kRootCrossSignedPEM));
  ScopedX509 intermediate(CertFromPEM(kIntermediatePEM));
  ScopedX509 intermediate_self_signed(CertFromPEM(kIntermediateSelfSignedPEM));
  ScopedX509 leaf(CertFromPEM(kLeafPEM));
  ScopedX509 leaf_no_key_usage(CertFromPEM(kLeafNoKeyUsagePEM));
  ScopedX509 forgery(CertFromPEM(kForgeryPEM));

  if (!cross_signing_root ||
      !root ||
      !root_cross_signed ||
      !intermediate ||
      !intermediate_self_signed ||
      !leaf ||
      !leaf_no_key_usage ||
      !forgery) {
    fprintf(stderr, "Failed to parse certificates\n");
    return false;
  }

  std::vector<X509*> empty;
  if (Verify(leaf.get(), empty, empty)) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return false;
  }

  if (Verify(leaf.get(), empty, {intermediate.get()})) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return false;
  }

  if (!Verify(leaf.get(), {root.get()}, {intermediate.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Basic chain didn't verify.\n");
    return false;
  }

  if (!Verify(leaf.get(), {cross_signing_root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain didn't verify.\n");
    return false;
  }

  if (!Verify(leaf.get(), {cross_signing_root.get(), root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain with root didn't verify.\n");
    return false;
  }

  /* This is the “altchains” test – we remove the cross-signing CA but include
   * the cross-sign in the intermediates. */
  if (!Verify(leaf.get(), {root.get()},
              {intermediate.get(), root_cross_signed.get()})) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Chain with cross-sign didn't backtrack to find root.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()},
             {intermediate.get(), root_cross_signed.get()},
             X509_V_FLAG_NO_ALT_CHAINS)) {
    fprintf(stderr, "Altchains test still passed when disabled.\n");
    return false;
  }

  if (Verify(forgery.get(), {intermediate_self_signed.get()},
             {leaf_no_key_usage.get()})) {
    fprintf(stderr, "Basic constraints weren't checked.\n");
    return false;
  }

  /* Test that one cannot skip Basic Constraints checking with a contorted set
   * of roots and intermediates. This is a regression test for CVE-2015-1793. */
  if (Verify(forgery.get(),
             {intermediate_self_signed.get(), root_cross_signed.get()},
             {leaf_no_key_usage.get(), intermediate.get()})) {
    fprintf(stderr, "Basic constraints weren't checked.\n");
    return false;
  }

  return true;
}

static bool TestPSS() {
  ScopedX509 cert(CertFromPEM(kExamplePSSCert));
  if (!cert) {
    return false;
  }

  ScopedEVP_PKEY pkey(X509_get_pubkey(cert.get()));
  if (!pkey) {
    return false;
  }

  if (!X509_verify(cert.get(), pkey.get())) {
    fprintf(stderr, "Could not verify certificate.\n");
    return false;
  }
  return true;
}

static bool TestBadPSSParameters() {
  ScopedX509 cert(CertFromPEM(kBadPSSCertPEM));
  if (!cert) {
    return false;
  }

  ScopedEVP_PKEY pkey(X509_get_pubkey(cert.get()));
  if (!pkey) {
    return false;
  }

  if (X509_verify(cert.get(), pkey.get())) {
    fprintf(stderr, "Unexpectedly verified bad certificate.\n");
    return false;
  }
  ERR_clear_error();
  return true;
}

static bool SignatureRoundTrips(EVP_MD_CTX *md_ctx, EVP_PKEY *pkey) {
  // Make a certificate like signed with |md_ctx|'s settings.'
  ScopedX509 cert(CertFromPEM(kLeafPEM));
  if (!cert || !X509_sign_ctx(cert.get(), md_ctx)) {
    return false;
  }

  // Ensure that |pkey| may still be used to verify the resulting signature. All
  // settings in |md_ctx| must have been serialized appropriately.
  return !!X509_verify(cert.get(), pkey);
}

static bool TestSignCtx() {
  ScopedEVP_PKEY pkey(PrivateKeyFromPEM(kRSAKey));
  if (!pkey) {
    return false;
  }

  // Test PKCS#1 v1.5.
  ScopedEVP_MD_CTX md_ctx;
  if (!EVP_DigestSignInit(md_ctx.get(), NULL, EVP_sha256(), NULL, pkey.get()) ||
      !SignatureRoundTrips(md_ctx.get(), pkey.get())) {
    fprintf(stderr, "RSA PKCS#1 with SHA-256 failed\n");
    return false;
  }

  // Test RSA-PSS with custom parameters.
  md_ctx.Reset();
  EVP_PKEY_CTX *pkey_ctx;
  if (!EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, EVP_sha256(), NULL,
                          pkey.get()) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha512()) ||
      !SignatureRoundTrips(md_ctx.get(), pkey.get())) {
    fprintf(stderr, "RSA-PSS failed\n");
    return false;
  }

  return true;
}

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (!TestVerify() ||
      !TestPSS() ||
      !TestBadPSSParameters() ||
      !TestSignCtx()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
