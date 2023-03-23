// OpenPGP.js - An OpenPGP implementation in javascript
// Copyright (C) 2015-2016 Decentral
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

/**
 * @fileoverview Key encryption and decryption for RFC 6637 ECDH
 * @module crypto/public_key/elliptic/ecdh
 * @private
 */

import nacl from '@openpgp/tweetnacl/nacl-fast-light';
import * as aesKW from '../../aes_kw';
import { getRandomBytes } from '../../random';

import enums from '../../../enums';
import util from '../../../util';
import getCipher from '../../cipher/getCipher';
import computeHKDF from '../../hkdf';

const HKDF_INFO = {
  x25519: util.encodeUTF8('OpenPGP X25519')
};

/**
 * Generate ECDH key for Montgomery curves
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @returns Promise<{ A, k }>
 */
export async function generate(algo) {
  switch (algo) {
    case enums.publicKey.x25519: {
      // k stays in little-endian, unlike legacy ECDH over curve25519
      const k = getRandomBytes(32);
      k[0] &= 248;
      k[31] = (k[31] & 127) | 64;
      const { publicKey: A } = nacl.box.keyPair.fromSecretKey(k);
      return { A, k };
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
* Validate ECDH parameters
* @param {module:enums.publicKey} algo - Algorithm identifier
* @param {Uint8Array} A - ECDH public point
* @param {Uint8Array} k - ECDH secret scalar
* @returns {Promise<Boolean>} Whether params are valid.
* @async
*/
export async function validateParams(algo, A, k) {
  switch (algo) {
    case enums.publicKey.x25519: {
      /**
       * Derive public point A' from private key
       * and expect A == A'
       */
      const { publicKey } = nacl.box.keyPair.fromSecretKey(k);
      return util.equalsUint8Array(A, publicKey);
    }

    default:
      return false;
  }
}

/**
 * Wrap and encrypt a session key
 *
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {Uint8Array} data - session key data to be encrypted
 * @param {Uint8Array} recipientA - Recipient public key (K_B)
 * @returns {Promise<{
 *  ephemeralPublicKey: Uint8Array,
 * wrappedKey: Uint8Array
 * }>} ephemeral public key (K_A) and encrypted key
 * @async
 */
export async function encrypt(algo, data, recipientA) {
  switch (algo) {
    case enums.publicKey.x25519: {
      const ephemeralSecretKey = getRandomBytes(32);
      const sharedSecret = nacl.scalarMult(ephemeralSecretKey, recipientA);
      const { publicKey: ephemeralPublicKey } = nacl.box.keyPair.fromSecretKey(ephemeralSecretKey);
      const { keySize } = getCipher(enums.symmetric.aes128);
      const encryptionKey = await computeHKDF(enums.hash.sha256, sharedSecret, new Uint8Array(), HKDF_INFO.x25519, keySize);
      const wrappedKey = aesKW.wrap(encryptionKey, data);
      return { ephemeralPublicKey, wrappedKey };
    }

    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}

/**
 * Decrypt and unwrap the session key
 *
 * @param {module:enums.publicKey} algo - Algorithm identifier
 * @param {Uint8Array} ephemeralPublicKey - (K_A)
 * @param {Uint8Array} wrappedKey
 * @param {Uint8Array} k - Recipient secret key (b)
 * @returns {Promise<Uint8Array>} decrypted session key data
 * @async
 */
export async function decrypt(algo, ephemeralPublicKey, wrappedKey, k) {
  switch (algo) {
    case enums.publicKey.x25519: {
      const sharedSecret = nacl.scalarMult(k, ephemeralPublicKey);
      const { keySize } = getCipher(enums.symmetric.aes128);
      const encryptionKey = await computeHKDF(enums.hash.sha256, sharedSecret, new Uint8Array(), HKDF_INFO.x25519, keySize);
      return aesKW.unwrap(encryptionKey, wrappedKey);
    }
    default:
      throw new Error('Unsupported ECDH algorithm');
  }
}
