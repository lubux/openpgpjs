// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import KeyID from '../type/keyid';
import crypto from '../crypto';
import enums from '../enums';
import util from '../util';
import { UnsupportedError } from './packet';

/**
 * Public-Key Encrypted Session Key Packets (Tag 1)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.1|RFC4880 5.1}:
 * A Public-Key Encrypted Session Key packet holds the session key
 * used to encrypt a message. Zero or more Public-Key Encrypted Session Key
 * packets and/or Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data Packet, which holds an encrypted message. The
 * message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s). The
 * Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their
 * public key, decrypts the session key, and then uses the session key to
 * decrypt the message.
 */
class PublicKeyEncryptedSessionKeyPacket {
  static get tag() {
    return enums.packet.publicKeyEncryptedSessionKey;
  }

  constructor() {
    this.version = null;

    // For version 3:
    this.publicKeyID = new KeyID();

    // For version 6:
    this.publicKeyVersion = null;
    this.publicKeyFingerprint = null;

    // For all versions:
    this.publicKeyAlgorithm = null;

    this.sessionKey = null;
    /**
     * Algorithm to encrypt the message with
     * @type {enums.symmetric}
     */
    this.sessionKeyAlgorithm = null;

    /** @type {Object} */
    this.encrypted = {};
  }

  /**
   * Parsing function for a publickey encrypted session key packet (tag 1).
   *
   * @param {Uint8Array} bytes - Payload of a tag 1 packet
   */
  read(bytes) {
    let offset = 0;
    this.version = bytes[offset++];
    if (this.version !== 3 && this.version !== 6) {
      throw new UnsupportedError(`Version ${this.version} of the PKESK packet is unsupported.`);
    }
    if (this.version === 6) {
      const sizeFields = bytes[offset++];
      if (sizeFields !== 0) {
        this.publicKeyVersion = bytes[offset++];
        const fingerprintLength = this.publicKeyVersion ? (this.publicKeyVersion >= 5 ? 32 : 20) : 0;
        this.publicKeyFingerprint = bytes.subarray(offset, offset + fingerprintLength);
        offset += fingerprintLength;
        if (this.publicKeyVersion >= 5) {
          // For v5/6 the Key ID is the high-order 64 bits of the fingerprint.
          this.publicKeyID.read(this.publicKeyFingerprint);
        } else {
          // For v4 The Key ID is the low-order 64 bits of the fingerprint.
          this.publicKeyID.read(this.publicKeyFingerprint.subarray(-8));
        }
      } else {
        // The size may also be zero, and the key version and 
        // fingerprint omitted for an "anonymous recipient" 
        this.publicKeyID = KeyID.wildcard();
      }
    } else {
      offset += this.publicKeyID.read(bytes.subarray(offset));
    }
    this.publicKeyAlgorithm = bytes[offset++];
    this.encrypted = crypto.parseEncSessionKeyParams(this.publicKeyAlgorithm, bytes.subarray(offset), this.version);
    if (this.version === 3 && (
      this.publicKeyAlgorithm === enums.publicKey.x25519 || this.publicKeyAlgorithm === enums.publicKey.x448)) {
      if (this.encrypted.metadata.length < 2) {
        throw new Error(`No session key algorithm for PKESK v3 packet.`);
      }
      this.sessionKeyAlgorithm = enums.write(enums.symmetric, this.encrypted.metadata[1]);
      if (!util.isAES(this.sessionKeyAlgorithm)) {
        throw new Error('Unexpected non-AES session key');
      }
    }
  }

  /**
   * Create a binary representation of a tag 1 packet
   *
   * @returns {Uint8Array} The Uint8Array representation.
   */
  write() {
    const arr = [
      new Uint8Array([this.version])
    ];

    if (this.version === 6) {
      if (this.publicKeyFingerprint !== null) {
        arr.push(new Uint8Array([
          this.publicKeyFingerprint.length + 1, 
          this.publicKeyVersion]
        ));
        arr.push(this.publicKeyFingerprint);
      } else {
        arr.push(new Uint8Array([0]));
      }
    } else {
      arr.push(this.publicKeyID.write());
    }

    arr.push(
      new Uint8Array([this.publicKeyAlgorithm]),
      crypto.serializeParams(this.publicKeyAlgorithm, this.encrypted)
    );

    return util.concatUint8Array(arr);
  }

  /**
   * Encrypt session key packet
   * @param {PublicKeyPacket} key - Public key
   * @throws {Error} if encryption failed
   * @async
   */
  async encrypt(key) {
    const algo = enums.write(enums.publicKey, this.publicKeyAlgorithm);
    if (this.version === 3 && !util.isAES(this.sessionKeyAlgorithm) && (algo === enums.publicKey.x25519 || algo === enums.publicKey.x448)) {
      // see https://gitlab.com/openpgp-wg/rfc4880bis/-/merge_requests/276
      throw new Error('X25519 and X448 keys can only encrypt AES session keys');
    }

    const encoded = encodeSessionKey(this.version, algo, this.sessionKeyAlgorithm, this.sessionKey);
    const skAlgorithm = this.version === 3 && (algo === enums.publicKey.x25519 || algo === enums.publicKey.x448) ? this.sessionKeyAlgorithm : undefined;
    this.encrypted = await crypto.publicKeyEncrypt(
      algo, key.publicParams, encoded, key.getFingerprintBytes(), skAlgorithm);
  }

  /**
   * Decrypts the session key (only for public key encrypted session key packets (tag 1)
   * @param {SecretKeyPacket} key - decrypted private key
   * @param {Object} [randomSessionKey] - Bogus session key to use in case of sensitive decryption error, or if the decrypted session key is of a different type/size.
   *                                      This is needed for constant-time processing. Expected object of the form: { sessionKey: Uint8Array, sessionKeyAlgorithm: enums.symmetric }
   * @throws {Error} if decryption failed, unless `randomSessionKey` is given
   * @async
   */
  async decrypt(key, randomSessionKey) {
    // check that session key algo matches the secret key algo
    if (this.publicKeyAlgorithm !== key.algorithm) {
      throw new Error('Decryption error');
    }

    const randomPayload = randomSessionKey ?
      encodeSessionKey(this.version, this.publicKeyAlgorithm, randomSessionKey.sessionKeyAlgorithm, randomSessionKey.sessionKey) :
      null;
    const decryptedData = await crypto.publicKeyDecrypt(this.publicKeyAlgorithm, key.publicParams, key.privateParams, this.encrypted, key.getFingerprintBytes(), randomPayload);

    const { sessionKey, sessionKeyAlgorithm } = decodeSessionKey(this.version, this.publicKeyAlgorithm, decryptedData, randomSessionKey);

    // v3 Montgomery curves have cleartext cipher algo
    if (this.version === 3 && (
      this.publicKeyAlgorithm !== enums.publicKey.x25519 && this.publicKeyAlgorithm !== enums.publicKey.x448)
    ) {
      this.sessionKeyAlgorithm = sessionKeyAlgorithm;
    }
    this.sessionKey = sessionKey;
  }
}

export default PublicKeyEncryptedSessionKeyPacket;


function encodeSessionKey(version, algo, cipherAlgo, sessionKeyData) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh: {
      // add checksum
      return util.concatUint8Array([
        new Uint8Array(version === 6 ? [] : [cipherAlgo]),
        sessionKeyData,
        util.writeChecksum(sessionKeyData.subarray(sessionKeyData.length % 8))
      ]);

    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      return sessionKeyData;
    }
    default:
      throw new Error('Unsupported public key algorithm');
  }
}


function decodeSessionKey(version, algo, decryptedData, randomSessionKey) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.elgamal:
    case enums.publicKey.ecdh: {
      // verify checksum in constant time
      const result = decryptedData.subarray(0, decryptedData.length - 2);
      const checksum = decryptedData.subarray(decryptedData.length - 2);
      const computedChecksum = util.writeChecksum(result.subarray(result.length % 8));
      const isValidChecksum = computedChecksum[0] === checksum[0] & computedChecksum[1] === checksum[1];
      const decryptedSessionKey = {
        sessionKeyAlgorithm: version === 6 ? null : result[0],
        sessionKey: version === 6 ? result : result.subarray(1)
      };
      if (randomSessionKey) {
        // We must not leak info about the validity of the decrypted checksum or cipher algo.
        // The decrypted session key must be of the same algo and size as the random session key, otherwise we discard it and use the random data.
        const isMatchingSessionKeyAlgorithm = version === 6 || decryptedSessionKey.sessionKeyAlgorithm === randomSessionKey.sessionKeyAlgorithm;
        const isValidPayload = isValidChecksum & isMatchingSessionKeyAlgorithm & decryptedSessionKey.sessionKey.length === randomSessionKey.sessionKey.length;
        return {
          sessionKey: util.selectUint8Array(isValidPayload, decryptedSessionKey.sessionKey, randomSessionKey.sessionKey),
          sessionKeyAlgorithm: version === 6 ? null : util.selectUint8(
            isValidPayload,
            decryptedSessionKey.sessionKeyAlgorithm,
            randomSessionKey.sessionKeyAlgorithm
          )
        };
      } else {
        const isValidPayload = isValidChecksum && (version === 6 || enums.read(enums.symmetric, decryptedSessionKey.sessionKeyAlgorithm));
        if (isValidPayload) {
          return decryptedSessionKey;
        } else {
          throw new Error('Decryption error');
        }
      }
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      return {
        sessionKey: decryptedData
      };
    }
    default:
      throw new Error('Unsupported public key algorithm');
  }
}
