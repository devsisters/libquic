// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CRYPTO_QUIC_DECRYPTER_H_
#define NET_QUIC_CRYPTO_QUIC_DECRYPTER_H_

#include "net/base/net_export.h"
#include "net/quic/quic_protocol.h"

namespace net {

class NET_EXPORT_PRIVATE QuicDecrypter {
 public:
  virtual ~QuicDecrypter() {}

  static QuicDecrypter* Create(QuicTag algorithm);

  // Sets the encryption key. Returns true on success, false on failure.
  //
  // NOTE: The key is the client_write_key or server_write_key derived from
  // the master secret.
  virtual bool SetKey(base::StringPiece key) = 0;

  // Sets the fixed initial bytes of the nonce. Returns true on success,
  // false on failure.
  //
  // NOTE: The nonce prefix is the client_write_iv or server_write_iv
  // derived from the master secret. A 64-bit packet sequence number will
  // be appended to form the nonce.
  //
  //                          <------------ 64 bits ----------->
  //   +---------------------+----------------------------------+
  //   |    Fixed prefix     |      Packet sequence number      |
  //   +---------------------+----------------------------------+
  //                          Nonce format
  //
  // The security of the nonce format requires that QUIC never reuse a
  // packet sequence number, even when retransmitting a lost packet.
  virtual bool SetNoncePrefix(base::StringPiece nonce_prefix) = 0;

  // Decrypt authenticates |associated_data| and |ciphertext| and then decrypts
  // |ciphertext| into |output|, using |nonce|. |nonce| must be 8 bytes longer
  // than the nonce prefix length returned by GetNoncePrefixSize() (of the
  // encrypter). |output| must be as long as |ciphertext| on entry and, on
  // successful return, the true length of the plaintext will be written to
  // |*output_length|.
  virtual bool Decrypt(base::StringPiece nonce,
                       base::StringPiece associated_data,
                       base::StringPiece ciphertext,
                       unsigned char* output,
                       size_t* output_length) = 0;

  // Returns a newly created QuicData object containing the decrypted
  // |ciphertext| or nullptr if there is an error. |sequence_number| is
  // appended to the |nonce_prefix| value provided in SetNoncePrefix()
  // to form the nonce.
  // TODO(wtc): add a way for DecryptPacket to report decryption failure due
  // to non-authentic inputs, as opposed to other reasons for failure.
  virtual QuicData* DecryptPacket(QuicPacketSequenceNumber sequence_number,
                                  base::StringPiece associated_data,
                                  base::StringPiece ciphertext) = 0;

  // For use by unit tests only.
  virtual base::StringPiece GetKey() const = 0;
  virtual base::StringPiece GetNoncePrefix() const = 0;
};

}  // namespace net

#endif  // NET_QUIC_CRYPTO_QUIC_DECRYPTER_H_
