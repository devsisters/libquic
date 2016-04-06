// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_PROOF_SOURCE_H_
#define NET_QUIC_CRYPTO_PROOF_SOURCE_H_

#include <string>
#include <vector>

#include "base/memory/ref_counted.h"
#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

class IPAddress;

// ProofSource is an interface by which a QUIC server can obtain certificate
// chains and signatures that prove its identity.
class NET_EXPORT_PRIVATE ProofSource {
 public:
  // Chain is a reference-counted wrapper for a std::vector of std::stringified
  // certificates.
  struct NET_EXPORT_PRIVATE Chain : public base::RefCounted<Chain> {
    explicit Chain(const std::vector<std::string>& certs);

    const std::vector<std::string> certs;

   private:
    friend class base::RefCounted<Chain>;

    virtual ~Chain();

    DISALLOW_COPY_AND_ASSIGN(Chain);
  };

  virtual ~ProofSource() {}

  // GetProof finds a certificate chain for |hostname|, sets |out_certs| to
  // point to it (in leaf-first order), calculates a signature of
  // |server_config| using that chain and puts the result in |out_signature|.
  //
  // The signature uses SHA-256 as the hash function and PSS padding when the
  // key is RSA.
  //
  // The signature uses SHA-256 as the hash function when the key is ECDSA.
  //
  // If |ecdsa_ok| is true, the signature may use an ECDSA key. Otherwise, the
  // signature must use an RSA key.
  //
  // |out_chain| is reference counted to avoid the (assumed) expense of copying
  // out the certificates.
  //
  // The number of certificate chains is expected to be small and fixed thus
  // the ProofSource retains ownership of the contents of |out_certs|. The
  // expectation is that they will be cached forever.
  //
  // For version before QUIC_VERSION_30, the signature values should be cached
  // because |server_config| will be somewhat static. However, since they aren't
  // bounded, the ProofSource may wish to evicit entries from that cache, thus
  // the caller takes ownership of |*out_signature|.
  //
  // For QUIC_VERSION_30 and later, the signature depends on |chlo_hash|
  // which means that the signature can not be cached. The caller takes
  // ownership of |*out_signature|.
  //
  // |hostname| may be empty to signify that a default certificate should be
  // used.
  //
  // |out_leaf_cert_sct| points to the signed timestamp (RFC6962) of the leaf
  // cert.
  // This function may be called concurrently.
  virtual bool GetProof(const IPAddress& server_ip,
                        const std::string& hostname,
                        const std::string& server_config,
                        QuicVersion quic_version,
                        base::StringPiece chlo_hash,
                        bool ecdsa_ok,
                        scoped_refptr<Chain>* out_chain,
                        std::string* out_signature,
                        std::string* out_leaf_cert_sct) = 0;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_PROOF_SOURCE_H_
