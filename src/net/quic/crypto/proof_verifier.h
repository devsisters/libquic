// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_PROOF_VERIFIER_H_
#define NET_QUIC_CRYPTO_PROOF_VERIFIER_H_

#include <string>
#include <vector>

#include "base/memory/scoped_ptr.h"
#include "net/base/net_export.h"
#include "net/quic/quic_types.h"

namespace net {

// ProofVerifyDetails is an abstract class that acts as a container for any
// implementation specific details that a ProofVerifier wishes to return. These
// details are saved in the CachedState for the origin in question.
class NET_EXPORT_PRIVATE ProofVerifyDetails {
 public:
  virtual ~ProofVerifyDetails() {}

  // Returns an new ProofVerifyDetails object with the same contents
  // as this one.
  virtual ProofVerifyDetails* Clone() const = 0;
};

// ProofVerifyContext is an abstract class that acts as a container for any
// implementation specific context that a ProofVerifier needs.
class NET_EXPORT_PRIVATE ProofVerifyContext {
 public:
  virtual ~ProofVerifyContext() {}
};

// ProofVerifierCallback provides a generic mechanism for a ProofVerifier to
// call back after an asynchronous verification.
class NET_EXPORT_PRIVATE ProofVerifierCallback {
 public:
  virtual ~ProofVerifierCallback() {}

  // Run is called on the original thread to mark the completion of an
  // asynchonous verification. If |ok| is true then the certificate is valid
  // and |error_details| is unused. Otherwise, |error_details| contains a
  // description of the error. |details| contains implementation-specific
  // details of the verification. |Run| may take ownership of |details| by
  // calling |release| on it.
  virtual void Run(bool ok,
                   const std::string& error_details,
                   scoped_ptr<ProofVerifyDetails>* details) = 0;
};

// A ProofVerifier checks the signature on a server config, and the certificate
// chain that backs the public key.
class NET_EXPORT_PRIVATE ProofVerifier {
 public:
  virtual ~ProofVerifier() {}

  // VerifyProof checks that |signature| is a valid signature of
  // |server_config| by the public key in the leaf certificate of |certs|, and
  // that |certs| is a valid chain for |hostname|. On success, it returns
  // QUIC_SUCCESS. On failure, it returns QUIC_FAILURE and sets |*error_details|
  // to a description of the problem. In either case it may set |*details|,
  // which the caller takes ownership of.
  //
  // |context| specifies an implementation specific struct (which may be nullptr
  // for some implementations) that provides useful information for the
  // verifier, e.g. logging handles.
  //
  // This function may also return QUIC_PENDING, in which case the ProofVerifier
  // will call back, on the original thread, via |callback| when complete.
  // In this case, the ProofVerifier will take ownership of |callback|.
  //
  // The signature uses SHA-256 as the hash function and PSS padding in the
  // case of RSA.
  virtual QuicAsyncStatus VerifyProof(const std::string& hostname,
                                      const std::string& server_config,
                                      const std::vector<std::string>& certs,
                                      const std::string& signature,
                                      const ProofVerifyContext* context,
                                      std::string* error_details,
                                      scoped_ptr<ProofVerifyDetails>* details,
                                      ProofVerifierCallback* callback) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_PROOF_VERIFIER_H_
