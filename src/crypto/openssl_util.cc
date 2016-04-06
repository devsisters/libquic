// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/openssl_util.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <stddef.h>
#include <stdint.h>

#include "base/logging.h"
#include "base/strings/string_piece.h"

namespace crypto {

namespace {

// Callback routine for OpenSSL to print error messages. |str| is a
// NULL-terminated string of length |len| containing diagnostic information
// such as the library, function and reason for the error, the file and line
// where the error originated, plus potentially any context-specific
// information about the error. |context| contains a pointer to user-supplied
// data, which is currently unused.
// If this callback returns a value <= 0, OpenSSL will stop processing the
// error queue and return, otherwise it will continue calling this function
// until all errors have been removed from the queue.
int OpenSSLErrorCallback(const char* str, size_t len, void* context) {
  DVLOG(1) << "\t" << base::StringPiece(str, len);
  return 1;
}

}  // namespace

void EnsureOpenSSLInit() {
  // CRYPTO_library_init may be safely called concurrently.
  CRYPTO_library_init();
}

void ClearOpenSSLERRStack(const tracked_objects::Location& location) {
  if (logging::DEBUG_MODE && VLOG_IS_ON(1)) {
    uint32_t error_num = ERR_peek_error();
    if (error_num == 0)
      return;

    std::string message;
    location.Write(true, true, &message);
    DVLOG(1) << "OpenSSL ERR_get_error stack from " << message;
    ERR_print_errors_cb(&OpenSSLErrorCallback, NULL);
  } else {
    ERR_clear_error();
  }
}

}  // namespace crypto
