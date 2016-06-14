// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_log_util.h"

#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/http/http_auth_challenge_tokenizer.h"
#include "net/http/http_auth_scheme.h"
#include "net/http/http_util.h"

namespace net {

namespace {

bool ShouldRedactChallenge(HttpAuthChallengeTokenizer* challenge) {
  // Ignore lines with commas, as they may contain lists of schemes, and
  // the information we want to hide is Base64 encoded, so has no commas.
  if (challenge->challenge_text().find(',') != std::string::npos)
    return false;

  std::string scheme = base::ToLowerASCII(challenge->scheme());
  // Invalid input.
  if (scheme.empty())
    return false;

  // Ignore Basic and Digest authentication challenges, as they contain
  // public information.
  if (scheme == kBasicAuthScheme || scheme == kDigestAuthScheme)
    return false;

  return true;
}

}  // namespace

std::string ElideHeaderValueForNetLog(NetLogCaptureMode capture_mode,
                                      const std::string& header,
                                      const std::string& value) {
  std::string::const_iterator redact_begin = value.begin();
  std::string::const_iterator redact_end = value.begin();

  if (redact_begin == redact_end &&
      !capture_mode.include_cookies_and_credentials()) {
    // Note: this logic should be kept in sync with stripCookieOrLoginInfo in
    // chrome/browser/resources/net_internals/log_view_painter.js.

    if (base::EqualsCaseInsensitiveASCII(header, "set-cookie") ||
        base::EqualsCaseInsensitiveASCII(header, "set-cookie2") ||
        base::EqualsCaseInsensitiveASCII(header, "cookie") ||
        base::EqualsCaseInsensitiveASCII(header, "authorization") ||
        base::EqualsCaseInsensitiveASCII(header, "proxy-authorization")) {
      redact_begin = value.begin();
      redact_end = value.end();
    } else if (base::EqualsCaseInsensitiveASCII(header, "www-authenticate") ||
               base::EqualsCaseInsensitiveASCII(header, "proxy-authenticate")) {
      // Look for authentication information from data received from the server
      // in multi-round Negotiate authentication.
      HttpAuthChallengeTokenizer challenge(value.begin(), value.end());
      if (ShouldRedactChallenge(&challenge)) {
        redact_begin = challenge.params_begin();
        redact_end = challenge.params_end();
      }
    }
  }

  if (redact_begin == redact_end)
    return value;

  return std::string(value.begin(), redact_begin) +
      base::StringPrintf("[%ld bytes were stripped]",
                         static_cast<long>(redact_end - redact_begin)) +
      std::string(redact_end, value.end());
}

std::string ElideGoAwayDebugDataForNetLog(NetLogCaptureMode capture_mode,
                                          base::StringPiece debug_data) {
  // Note: this logic should be kept in sync with stripGoAwayDebugData in
  // chrome/browser/resources/net_internals/log_view_painter.js.
  if (capture_mode.include_cookies_and_credentials()) {
    return debug_data.as_string();
  }

  return std::string("[") + base::SizeTToString(debug_data.size()) +
         std::string(" bytes were stripped]");
}

std::unique_ptr<base::ListValue> ElideSpdyHeaderBlockForNetLog(
    const SpdyHeaderBlock& headers,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::ListValue> headers_list(new base::ListValue());
  for (SpdyHeaderBlock::const_iterator it = headers.begin();
       it != headers.end(); ++it) {
    headers_list->AppendString(
        it->first.as_string() + ": " +
        ElideHeaderValueForNetLog(capture_mode, it->first.as_string(),
                                  it->second.as_string()));
  }
  return headers_list;
}

}  // namespace net
