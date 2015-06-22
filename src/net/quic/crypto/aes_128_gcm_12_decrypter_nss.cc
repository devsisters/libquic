// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/aes_128_gcm_12_decrypter.h"

#include <pk11pub.h>
#include <secerr.h>

#include "base/lazy_instance.h"
#include "crypto/ghash.h"
#include "crypto/scoped_nss_types.h"

#if defined(USE_NSS_CERTS)
#include <dlfcn.h>
#endif

using base::StringPiece;

namespace net {

namespace {

const size_t kKeySize = 16;
const size_t kNoncePrefixSize = 4;

// On Linux, dynamically link against the system version of libnss3.so. In
// order to continue working on systems without up-to-date versions of NSS,
// lookup PK11_Decrypt with dlsym.

// GcmSupportChecker is a singleton which caches the results of runtime symbol
// resolution of PK11_Decrypt.
class GcmSupportChecker {
 public:
  static PK11_DecryptFunction pk11_decrypt_func() {
    return pk11_decrypt_func_;
  }

 private:
  friend struct base::DefaultLazyInstanceTraits<GcmSupportChecker>;

  GcmSupportChecker() {
#if !defined(USE_NSS_CERTS)
    // Using a bundled version of NSS that is guaranteed to have this symbol.
    pk11_decrypt_func_ = PK11_Decrypt;
#else
    // Using system NSS libraries and PCKS #11 modules, which may not have the
    // necessary function (PK11_Decrypt) or mechanism support (CKM_AES_GCM).

    // If PK11_Decrypt() was successfully resolved, then NSS will support
    // AES-GCM directly. This was introduced in NSS 3.15.
    pk11_decrypt_func_ = (PK11_DecryptFunction)dlsym(RTLD_DEFAULT,
                                                     "PK11_Decrypt");
#endif
  }

  // |pk11_decrypt_func_| stores the runtime symbol resolution of PK11_Decrypt.
  static PK11_DecryptFunction pk11_decrypt_func_;
};

// static
PK11_DecryptFunction GcmSupportChecker::pk11_decrypt_func_ = nullptr;

base::LazyInstance<GcmSupportChecker>::Leaky g_gcm_support_checker =
    LAZY_INSTANCE_INITIALIZER;

// Calls PK11_Decrypt if it's available.  Otherwise, emulates CKM_AES_GCM using
// CKM_AES_CTR and the GaloisHash class.
SECStatus My_Decrypt(PK11SymKey* key,
                     CK_MECHANISM_TYPE mechanism,
                     SECItem* param,
                     unsigned char* out,
                     unsigned int* out_len,
                     unsigned int max_len,
                     const unsigned char* enc,
                     unsigned int enc_len) {
  // If PK11_Decrypt() was successfully resolved or if bundled version of NSS is
  // being used, then NSS will support AES-GCM directly.
  PK11_DecryptFunction pk11_decrypt_func =
      GcmSupportChecker::pk11_decrypt_func();
  if (pk11_decrypt_func != nullptr) {
    return pk11_decrypt_func(key, mechanism, param, out, out_len, max_len, enc,
                             enc_len);
  }

  // Otherwise, the user has an older version of NSS. Regrettably, NSS 3.14.x
  // has a bug in the AES GCM code
  // (https://bugzilla.mozilla.org/show_bug.cgi?id=853285), as well as missing
  // the PK11_Decrypt function
  // (https://bugzilla.mozilla.org/show_bug.cgi?id=854063), both of which are
  // resolved in NSS 3.15.

  DCHECK_EQ(mechanism, static_cast<CK_MECHANISM_TYPE>(CKM_AES_GCM));
  DCHECK_EQ(param->len, sizeof(CK_GCM_PARAMS));

  const CK_GCM_PARAMS* gcm_params =
      reinterpret_cast<CK_GCM_PARAMS*>(param->data);

  DCHECK_EQ(gcm_params->ulTagBits,
            static_cast<CK_ULONG>(Aes128Gcm12Decrypter::kAuthTagSize * 8));
  if (gcm_params->ulIvLen != 12u) {
    DVLOG(1) << "ulIvLen is not equal to 12";
    PORT_SetError(SEC_ERROR_INPUT_LEN);
    return SECFailure;
  }

  SECItem my_param = { siBuffer, nullptr, 0 };

  // Step 2. Let H = CIPH_K(128 '0' bits).
  unsigned char ghash_key[16] = {0};
  crypto::ScopedPK11Context ctx(PK11_CreateContextBySymKey(
      CKM_AES_ECB, CKA_ENCRYPT, key, &my_param));
  if (!ctx) {
    DVLOG(1) << "PK11_CreateContextBySymKey failed";
    return SECFailure;
  }
  int output_len;
  if (PK11_CipherOp(ctx.get(), ghash_key, &output_len, sizeof(ghash_key),
                    ghash_key, sizeof(ghash_key)) != SECSuccess) {
    DVLOG(1) << "PK11_CipherOp failed";
    return SECFailure;
  }

  PK11_Finalize(ctx.get());

  if (output_len != sizeof(ghash_key)) {
    DVLOG(1) << "Wrong output length";
    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
  }

  // Step 3. If len(IV)=96, then let J0 = IV || 31 '0' bits || 1.
  CK_AES_CTR_PARAMS ctr_params = {0};
  ctr_params.ulCounterBits = 32;
  memcpy(ctr_params.cb, gcm_params->pIv, gcm_params->ulIvLen);
  ctr_params.cb[12] = 0;
  ctr_params.cb[13] = 0;
  ctr_params.cb[14] = 0;
  ctr_params.cb[15] = 1;

  my_param.type = siBuffer;
  my_param.data = reinterpret_cast<unsigned char*>(&ctr_params);
  my_param.len = sizeof(ctr_params);

  ctx.reset(PK11_CreateContextBySymKey(CKM_AES_CTR, CKA_ENCRYPT, key,
                                       &my_param));
  if (!ctx) {
    DVLOG(1) << "PK11_CreateContextBySymKey failed";
    return SECFailure;
  }

  // Step 6. Calculate the encryption mask of GCTR_K(J0, ...).
  unsigned char tag_mask[16] = {0};
  if (PK11_CipherOp(ctx.get(), tag_mask, &output_len, sizeof(tag_mask),
                    tag_mask, sizeof(tag_mask)) != SECSuccess) {
    DVLOG(1) << "PK11_CipherOp failed";
    return SECFailure;
  }
  if (output_len != sizeof(tag_mask)) {
    DVLOG(1) << "Wrong output length";
    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
  }

  if (enc_len < Aes128Gcm12Decrypter::kAuthTagSize) {
    PORT_SetError(SEC_ERROR_INPUT_LEN);
    return SECFailure;
  }

  // The const_cast for |enc| can be removed if system NSS libraries are
  // NSS 3.14.1 or later (NSS bug
  // https://bugzilla.mozilla.org/show_bug.cgi?id=808218).
  if (PK11_CipherOp(ctx.get(), out, &output_len, max_len,
          const_cast<unsigned char*>(enc),
          enc_len - Aes128Gcm12Decrypter::kAuthTagSize) != SECSuccess) {
    DVLOG(1) << "PK11_CipherOp failed";
    return SECFailure;
  }

  PK11_Finalize(ctx.get());

  if (static_cast<unsigned int>(output_len) !=
      enc_len - Aes128Gcm12Decrypter::kAuthTagSize) {
    DVLOG(1) << "Wrong output length";
    PORT_SetError(SEC_ERROR_LIBRARY_FAILURE);
    return SECFailure;
  }

  crypto::GaloisHash ghash(ghash_key);
  ghash.UpdateAdditional(gcm_params->pAAD, gcm_params->ulAADLen);
  ghash.UpdateCiphertext(enc, output_len);
  unsigned char auth_tag[Aes128Gcm12Decrypter::kAuthTagSize];
  ghash.Finish(auth_tag, Aes128Gcm12Decrypter::kAuthTagSize);
  for (unsigned int i = 0; i < Aes128Gcm12Decrypter::kAuthTagSize; i++) {
    auth_tag[i] ^= tag_mask[i];
  }

  if (NSS_SecureMemcmp(auth_tag, enc + output_len,
                       Aes128Gcm12Decrypter::kAuthTagSize) != 0) {
    PORT_SetError(SEC_ERROR_BAD_DATA);
    return SECFailure;
  }

  *out_len = output_len;
  return SECSuccess;
}

}  // namespace

Aes128Gcm12Decrypter::Aes128Gcm12Decrypter()
    : AeadBaseDecrypter(CKM_AES_GCM, My_Decrypt, kKeySize, kAuthTagSize,
                        kNoncePrefixSize) {
  static_assert(kKeySize <= kMaxKeySize, "key size too big");
  static_assert(kNoncePrefixSize <= kMaxNoncePrefixSize,
                "nonce prefix size too big");
  ignore_result(g_gcm_support_checker.Get());
}

Aes128Gcm12Decrypter::~Aes128Gcm12Decrypter() {}

void Aes128Gcm12Decrypter::FillAeadParams(StringPiece nonce,
                                          const StringPiece& associated_data,
                                          size_t auth_tag_size,
                                          AeadParams* aead_params) const {
  aead_params->len = sizeof(aead_params->data.gcm_params);
  CK_GCM_PARAMS* gcm_params = &aead_params->data.gcm_params;
  gcm_params->pIv =
      reinterpret_cast<CK_BYTE*>(const_cast<char*>(nonce.data()));
  gcm_params->ulIvLen = nonce.size();
  gcm_params->pAAD =
      reinterpret_cast<CK_BYTE*>(const_cast<char*>(associated_data.data()));
  gcm_params->ulAADLen = associated_data.size();
  gcm_params->ulTagBits = auth_tag_size * 8;
}

}  // namespace net
