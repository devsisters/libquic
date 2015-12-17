// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/common_cert_set.h"

#include "base/basictypes.h"
#include "base/logging.h"
#include "base/memory/singleton.h"
#include "net/quic/quic_utils.h"

using base::StringPiece;

namespace net {

namespace common_cert_set_1 {
#include "net/quic/crypto/common_cert_set_1.c"
}

namespace {

struct CertSet {
  // num_certs contains the number of certificates in this set.
  size_t num_certs;
  // certs is an array of |num_certs| pointers to the DER encoded certificates.
  const unsigned char* const* certs;
  // lens is an array of |num_certs| integers describing the length, in bytes,
  // of each certificate.
  const size_t* lens;
  // hash contains the 64-bit, FNV-1a hash of this set.
  uint64 hash;
};

const CertSet kSets[] = {
  {
    common_cert_set_1::kNumCerts,
    common_cert_set_1::kCerts,
    common_cert_set_1::kLens,
    common_cert_set_1::kHash,
  },
};

const uint64 kSetHashes[] = {
  common_cert_set_1::kHash,
};

// Compare returns a value less than, equal to or greater than zero if |a| is
// lexicographically less than, equal to or greater than |b|, respectively.
int Compare(StringPiece a, const unsigned char* b, size_t b_len) {
  size_t len = a.size();
  if (len > b_len) {
    len = b_len;
  }
  int n = memcmp(a.data(), b, len);
  if (n != 0) {
    return n;
  }

  if (a.size() < b_len) {
    return -1;
  } else if (a.size() > b_len) {
    return 1;
  }
  return 0;
}

// CommonCertSetsQUIC implements the CommonCertSets interface using the default
// certificate sets.
class CommonCertSetsQUIC : public CommonCertSets {
 public:
  // CommonCertSets interface.
  StringPiece GetCommonHashes() const override {
    return StringPiece(reinterpret_cast<const char*>(kSetHashes),
                       sizeof(uint64) * arraysize(kSetHashes));
  }

  StringPiece GetCert(uint64 hash, uint32 index) const override {
    for (size_t i = 0; i < arraysize(kSets); i++) {
      if (kSets[i].hash == hash) {
        if (index < kSets[i].num_certs) {
          return StringPiece(
              reinterpret_cast<const char*>(kSets[i].certs[index]),
              kSets[i].lens[index]);
        }
        break;
      }
    }

    return StringPiece();
  }

  bool MatchCert(StringPiece cert,
                 StringPiece common_set_hashes,
                 uint64* out_hash,
                 uint32* out_index) const override {
    if (common_set_hashes.size() % sizeof(uint64) != 0) {
      return false;
    }

    for (size_t i = 0; i < common_set_hashes.size() / sizeof(uint64); i++) {
      uint64 hash;
      memcpy(&hash, common_set_hashes.data() + i * sizeof(uint64),
             sizeof(uint64));

      for (size_t j = 0; j < arraysize(kSets); j++) {
        if (kSets[j].hash != hash) {
          continue;
        }

        if (kSets[j].num_certs == 0) {
          continue;
        }

        // Binary search for a matching certificate.
        size_t min = 0;
        size_t max = kSets[j].num_certs - 1;
        while (max >= min) {
          size_t mid = min + ((max - min) / 2);
          int n = Compare(cert, kSets[j].certs[mid], kSets[j].lens[mid]);
          if (n < 0) {
            if (mid == 0) {
              break;
            }
            max = mid - 1;
          } else if (n > 0) {
            min = mid + 1;
          } else {
            *out_hash = hash;
            *out_index = mid;
            return true;
          }
        }
      }
    }

    return false;
  }

  static CommonCertSetsQUIC* GetInstance() {
    return base::Singleton<CommonCertSetsQUIC>::get();
  }

 private:
  CommonCertSetsQUIC() {}
  ~CommonCertSetsQUIC() override {}

  friend struct base::DefaultSingletonTraits<CommonCertSetsQUIC>;
  DISALLOW_COPY_AND_ASSIGN(CommonCertSetsQUIC);
};

}  // anonymous namespace

CommonCertSets::~CommonCertSets() {}

// static
const CommonCertSets* CommonCertSets::GetInstanceQUIC() {
  return CommonCertSetsQUIC::GetInstance();
}

}  // namespace net
