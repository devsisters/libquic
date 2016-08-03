#include <boringssl/bssl.h>
/* Copyright (c) 2014, Google Inc.
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

#include <stdint.h>
#include <string.h>

#include <vector>

#include <boringssl/aead.h>
#include <boringssl/crypto.h>
#include <boringssl/err.h>

#include "../test/file_test.h"
#include "../test/scoped_types.h"


// This program tests an AEAD against a series of test vectors from a file,
// using the FileTest format. As an example, here's a valid test case:
//
//   KEY: 5a19f3173586b4c42f8412f4d5a786531b3231753e9e00998aec12fda8df10e4
//   NONCE: 978105dfce667bf4
//   IN: 6a4583908d
//   AD: b654574932
//   CT: 5294265a60
//   TAG: 1d45758621762e061368e68868e2f929

static bool TestAEAD(FileTest *t, void *arg) {
  const EVP_AEAD *aead = reinterpret_cast<const EVP_AEAD*>(arg);

  std::vector<uint8_t> key, nonce, in, ad, ct, tag;
  if (!t->GetBytes(&key, "KEY") ||
      !t->GetBytes(&nonce, "NONCE") ||
      !t->GetBytes(&in, "IN") ||
      !t->GetBytes(&ad, "AD") ||
      !t->GetBytes(&ct, "CT") ||
      !t->GetBytes(&tag, "TAG")) {
    return false;
  }

  ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag.size(), evp_aead_seal)) {
    t->PrintLine("Failed to init AEAD.");
    return false;
  }

  std::vector<uint8_t> out(in.size() + EVP_AEAD_max_overhead(aead));
  if (!t->HasAttribute("NO_SEAL")) {
    size_t out_len;
    if (!EVP_AEAD_CTX_seal(ctx.get(), out.data(), &out_len, out.size(),
                           nonce.data(), nonce.size(), in.data(), in.size(),
                           ad.data(), ad.size())) {
      t->PrintLine("Failed to run AEAD.");
      return false;
    }
    out.resize(out_len);

    if (out.size() != ct.size() + tag.size()) {
      t->PrintLine("Bad output length: %u vs %u.", (unsigned)out_len,
                   (unsigned)(ct.size() + tag.size()));
      return false;
    }
    if (!t->ExpectBytesEqual(ct.data(), ct.size(), out.data(), ct.size()) ||
        !t->ExpectBytesEqual(tag.data(), tag.size(), out.data() + ct.size(),
                             tag.size())) {
      return false;
    }
  } else {
    out.resize(ct.size() + tag.size());
    memcpy(out.data(), ct.data(), ct.size());
    memcpy(out.data() + ct.size(), tag.data(), tag.size());
  }

  // The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
  // reset after each operation.
  ctx.Reset();
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag.size(), evp_aead_open)) {
    t->PrintLine("Failed to init AEAD.");
    return false;
  }

  std::vector<uint8_t> out2(out.size());
  size_t out2_len;
  int ret = EVP_AEAD_CTX_open(ctx.get(), out2.data(), &out2_len, out2.size(),
                              nonce.data(), nonce.size(), out.data(),
                              out.size(), ad.data(), ad.size());
  if (t->HasAttribute("FAILS")) {
    if (ret) {
      t->PrintLine("Decrypted bad data.");
      return false;
    }
    ERR_clear_error();
    return true;
  }

  if (!ret) {
    t->PrintLine("Failed to decrypt.");
    return false;
  }
  out2.resize(out2_len);
  if (!t->ExpectBytesEqual(in.data(), in.size(), out2.data(), out2.size())) {
    return false;
  }

  // The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
  // reset after each operation.
  ctx.Reset();
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag.size(), evp_aead_open)) {
    t->PrintLine("Failed to init AEAD.");
    return false;
  }

  // Garbage at the end isn't ignored.
  out.push_back(0);
  out2.resize(out.size());
  if (EVP_AEAD_CTX_open(ctx.get(), out2.data(), &out2_len, out2.size(),
                        nonce.data(), nonce.size(), out.data(), out.size(),
                        ad.data(), ad.size())) {
    t->PrintLine("Decrypted bad data with trailing garbage.");
    return false;
  }
  ERR_clear_error();

  // The "stateful" AEADs for implementing pre-AEAD cipher suites need to be
  // reset after each operation.
  ctx.Reset();
  if (!EVP_AEAD_CTX_init_with_direction(ctx.get(), aead, key.data(), key.size(),
                                        tag.size(), evp_aead_open)) {
    t->PrintLine("Failed to init AEAD.");
    return false;
  }

  // Verify integrity is checked.
  out[0] ^= 0x80;
  out.resize(out.size() - 1);
  out2.resize(out.size());
  if (EVP_AEAD_CTX_open(ctx.get(), out2.data(), &out2_len, out2.size(),
                        nonce.data(), nonce.size(), out.data(), out.size(),
                        ad.data(), ad.size())) {
    t->PrintLine("Decrypted bad data with corrupted byte.");
    return false;
  }
  ERR_clear_error();

  return true;
}

static int TestCleanupAfterInitFailure(const EVP_AEAD *aead) {
  EVP_AEAD_CTX ctx;
  uint8_t key[128];

  memset(key, 0, sizeof(key));
  const size_t key_len = EVP_AEAD_key_length(aead);
  if (key_len > sizeof(key)) {
    fprintf(stderr, "Key length of AEAD too long.\n");
    return 0;
  }

  if (EVP_AEAD_CTX_init(&ctx, aead, key, key_len,
                        9999 /* a silly tag length to trigger an error */,
                        NULL /* ENGINE */) != 0) {
    fprintf(stderr, "A silly tag length didn't trigger an error!\n");
    return 0;
  }
  ERR_clear_error();

  /* Running a second, failed _init should not cause a memory leak. */
  if (EVP_AEAD_CTX_init(&ctx, aead, key, key_len,
                        9999 /* a silly tag length to trigger an error */,
                        NULL /* ENGINE */) != 0) {
    fprintf(stderr, "A silly tag length didn't trigger an error!\n");
    return 0;
  }
  ERR_clear_error();

  /* Calling _cleanup on an |EVP_AEAD_CTX| after a failed _init should be a
   * no-op. */
  EVP_AEAD_CTX_cleanup(&ctx);
  return 1;
}

static bool TestWithAliasedBuffers(const EVP_AEAD *aead) {
  const size_t key_len = EVP_AEAD_key_length(aead);
  const size_t nonce_len = EVP_AEAD_nonce_length(aead);
  const size_t max_overhead = EVP_AEAD_max_overhead(aead);

  std::vector<uint8_t> key(key_len, 'a');
  ScopedEVP_AEAD_CTX ctx;
  if (!EVP_AEAD_CTX_init(ctx.get(), aead, key.data(), key_len,
                         EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)) {
    return false;
  }

  static const uint8_t kPlaintext[260] =
      "testing123456testing123456testing123456testing123456testing123456testing"
      "123456testing123456testing123456testing123456testing123456testing123456t"
      "esting123456testing123456testing123456testing123456testing123456testing1"
      "23456testing123456testing123456testing12345";
  const std::vector<size_t> offsets = {
      0,  1,  2,  8,  15, 16,  17,  31,  32,  33,  63,
      64, 65, 95, 96, 97, 127, 128, 129, 255, 256, 257,
  };

  std::vector<uint8_t> nonce(nonce_len, 'b');
  std::vector<uint8_t> valid_encryption(sizeof(kPlaintext) + max_overhead);
  size_t valid_encryption_len;
  if (!EVP_AEAD_CTX_seal(
          ctx.get(), valid_encryption.data(), &valid_encryption_len,
          sizeof(kPlaintext) + max_overhead, nonce.data(), nonce_len,
          kPlaintext, sizeof(kPlaintext), nullptr, 0)) {
    fprintf(stderr, "EVP_AEAD_CTX_seal failed with disjoint buffers.\n");
    return false;
  }

  // First test with out > in, which we expect to fail.
  for (auto offset : offsets) {
    if (offset == 0) {
      // Will be tested in the next loop.
      continue;
    }

    std::vector<uint8_t> buffer(offset + valid_encryption_len);
    memcpy(buffer.data(), kPlaintext, sizeof(kPlaintext));
    uint8_t *out = buffer.data() + offset;

    size_t out_len;
    if (!EVP_AEAD_CTX_seal(ctx.get(), out, &out_len,
                           sizeof(kPlaintext) + max_overhead, nonce.data(),
                           nonce_len, buffer.data(), sizeof(kPlaintext),
                           nullptr, 0)) {
      // We expect offsets where the output is greater than the input to fail.
      ERR_clear_error();
    } else {
      fprintf(stderr,
              "EVP_AEAD_CTX_seal unexpectedly succeeded for offset %u.\n",
              static_cast<unsigned>(offset));
      return false;
    }

    memcpy(buffer.data(), valid_encryption.data(), valid_encryption_len);
    if (!EVP_AEAD_CTX_open(ctx.get(), out, &out_len, valid_encryption_len,
                           nonce.data(), nonce_len, buffer.data(),
                           valid_encryption_len, nullptr, 0)) {
      // We expect offsets where the output is greater than the input to fail.
      ERR_clear_error();
    } else {
      fprintf(stderr,
              "EVP_AEAD_CTX_open unexpectedly succeeded for offset %u.\n",
              static_cast<unsigned>(offset));
      ERR_print_errors_fp(stderr);
      return false;
    }
  }

  // Test with out <= in, which we expect to work.
  for (auto offset : offsets) {
    std::vector<uint8_t> buffer(offset + valid_encryption_len);
    uint8_t *const out = buffer.data();
    uint8_t *const in = buffer.data() + offset;
    memcpy(in, kPlaintext, sizeof(kPlaintext));

    size_t out_len;
    if (!EVP_AEAD_CTX_seal(ctx.get(), out, &out_len,
                           sizeof(kPlaintext) + max_overhead, nonce.data(),
                           nonce_len, in, sizeof(kPlaintext), nullptr, 0)) {
      fprintf(stderr, "EVP_AEAD_CTX_seal failed for offset -%u.\n",
              static_cast<unsigned>(offset));
      return false;
    }

    if (out_len != valid_encryption_len ||
        memcmp(out, valid_encryption.data(), out_len) != 0) {
      fprintf(stderr, "EVP_AEAD_CTX_seal produced bad output for offset -%u.\n",
              static_cast<unsigned>(offset));
      return false;
    }

    memcpy(in, valid_encryption.data(), valid_encryption_len);
    if (!EVP_AEAD_CTX_open(ctx.get(), out, &out_len,
                           offset + valid_encryption_len, nonce.data(),
                           nonce_len, in, valid_encryption_len, nullptr, 0)) {
      fprintf(stderr, "EVP_AEAD_CTX_open failed for offset -%u.\n",
              static_cast<unsigned>(offset));
      return false;
    }

    if (out_len != sizeof(kPlaintext) ||
        memcmp(out, kPlaintext, out_len) != 0) {
      fprintf(stderr, "EVP_AEAD_CTX_open produced bad output for offset -%u.\n",
              static_cast<unsigned>(offset));
      return false;
    }
  }

  return true;
}

struct KnownAEAD {
  const char name[40];
  const EVP_AEAD *(*func)(void);
  // limited_implementation indicates that tests that assume a generic AEAD
  // interface should not be performed. For example, the key-wrap AEADs only
  // handle inputs that are a multiple of eight bytes in length and the
  // SSLv3/TLS AEADs have the concept of “direction”.
  bool limited_implementation;
};

static const struct KnownAEAD kAEADs[] = {
  { "aes-128-gcm", EVP_aead_aes_128_gcm, false },
  { "aes-256-gcm", EVP_aead_aes_256_gcm, false },
  { "chacha20-poly1305", EVP_aead_chacha20_poly1305, false },
  { "chacha20-poly1305-old", EVP_aead_chacha20_poly1305_old, false },
  { "rc4-md5-tls", EVP_aead_rc4_md5_tls, true },
  { "rc4-sha1-tls", EVP_aead_rc4_sha1_tls, true },
  { "aes-128-cbc-sha1-tls", EVP_aead_aes_128_cbc_sha1_tls, true },
  { "aes-128-cbc-sha1-tls-implicit-iv", EVP_aead_aes_128_cbc_sha1_tls_implicit_iv, true },
  { "aes-128-cbc-sha256-tls", EVP_aead_aes_128_cbc_sha256_tls, true },
  { "aes-256-cbc-sha1-tls", EVP_aead_aes_256_cbc_sha1_tls, true },
  { "aes-256-cbc-sha1-tls-implicit-iv", EVP_aead_aes_256_cbc_sha1_tls_implicit_iv, true },
  { "aes-256-cbc-sha256-tls", EVP_aead_aes_256_cbc_sha256_tls, true },
  { "aes-256-cbc-sha384-tls", EVP_aead_aes_256_cbc_sha384_tls, true },
  { "des-ede3-cbc-sha1-tls", EVP_aead_des_ede3_cbc_sha1_tls, true },
  { "des-ede3-cbc-sha1-tls-implicit-iv", EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv, true },
  { "rc4-md5-ssl3", EVP_aead_rc4_md5_ssl3, true },
  { "rc4-sha1-ssl3", EVP_aead_rc4_sha1_ssl3, true },
  { "aes-128-cbc-sha1-ssl3", EVP_aead_aes_128_cbc_sha1_ssl3, true },
  { "aes-256-cbc-sha1-ssl3", EVP_aead_aes_256_cbc_sha1_ssl3, true },
  { "des-ede3-cbc-sha1-ssl3", EVP_aead_des_ede3_cbc_sha1_ssl3, true },
  { "aes-128-key-wrap", EVP_aead_aes_128_key_wrap, true },
  { "aes-256-key-wrap", EVP_aead_aes_256_key_wrap, true },
  { "aes-128-ctr-hmac-sha256", EVP_aead_aes_128_ctr_hmac_sha256, false },
  { "aes-256-ctr-hmac-sha256", EVP_aead_aes_256_ctr_hmac_sha256, false },
  { "", NULL, false },
};

int main(int argc, char **argv) {
  CRYPTO_library_init();

  if (argc != 3) {
    fprintf(stderr, "%s <aead> <test file.txt>\n", argv[0]);
    return 1;
  }

  const struct KnownAEAD *known_aead;
  for (unsigned i = 0;; i++) {
    known_aead = &kAEADs[i];
    if (known_aead->func == NULL) {
      fprintf(stderr, "Unknown AEAD: %s\n", argv[1]);
      return 2;
    }
    if (strcmp(known_aead->name, argv[1]) == 0) {
      break;
    }
  }

  const EVP_AEAD *const aead = known_aead->func();

  if (!TestCleanupAfterInitFailure(aead)) {
    return 1;
  }

  if (!known_aead->limited_implementation && !TestWithAliasedBuffers(aead)) {
    fprintf(stderr, "Aliased buffers test failed for %s.\n", known_aead->name);
    return 1;
  }

  return FileTestMain(TestAEAD, const_cast<EVP_AEAD*>(aead), argv[2]);
}
