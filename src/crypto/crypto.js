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

// The GPG4Browsers crypto interface

/**
 * @fileoverview Provides functions for asymmetric encryption and decryption as
 * well as key generation and parameter handling for all public-key cryptosystems.
 * @module crypto/crypto
 * @private
 */

import publicKey from './public_key';
import mode from './mode';
import { getRandomBytes } from './random';
import getCipher from './cipher/getCipher';
import ECDHSymkey from '../type/ecdh_symkey';
import KDFParams from '../type/kdf_params';
import enums from '../enums';
import util from '../util';
import OID from '../type/oid';
import { UnsupportedError } from '../packet/packet';
/**
 * Encrypts data using specified algorithm and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Uint8Array} sessionKey - The session key to encrypt
 * @param {Uint8Array} fingerprint - Recipient fingerprint
 * @param {module:enums.symmetric} sessionKeyAlgorithm - Algorithm the session key is used for
 * @param {Number} version - The PKESK version to encrypt to
 * @returns {Promise<Object>} Encrypted session key parameters.
 * @async
 */
export async function publicKeyEncrypt(algo, publicParams, sessionKey, fingerprint, sessionKeyAlgorithm, version) {
  const data = encodeSessionKey(version, algo, sessionKeyAlgorithm, sessionKey);
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const { n, e } = publicParams;
      const c = await publicKey.rsa.encrypt(data, n, e);
      return { c };
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      return publicKey.elgamal.encrypt(data, p, g, y);
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicParams;
      const { publicKey: V, wrappedKey: C } = await publicKey.elliptic.ecdh.encrypt(
        oid, kdfParams, data, Q, fingerprint);
      return { V, C: new ECDHSymkey(C) };
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const { A } = publicParams;
      const { ephemeralPublicKey, wrappedKey } = await publicKey.elliptic.ecdhMontgomery.encrypt(
        algo, data, A);
      const followLength = wrappedKey.length;
      if (version === 3 && !util.isAES(sessionKeyAlgorithm)) {
        // see https://gitlab.com/openpgp-wg/rfc4880bis/-/merge_requests/276
        throw new Error('X25519 and X448 keys can only encrypt AES session keys');
      }
      const metadata = version === 3 ? 
        new Uint8Array([followLength + 1, sessionKeyAlgorithm]): 
        new Uint8Array([followLength]);
      return { ephemeralPublicKey, metadata, C: wrappedKey };
     
    }
    default:
      return [];
  }
}

/**
 * Decrypts data using specified algorithm and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 5.5.3}
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Object} publicKeyParams - Algorithm-specific public key parameters
 * @param {Object} privateKeyParams - Algorithm-specific private key parameters
 * @param {Object} sessionKeyParams - Encrypted session key parameters
 * @param {Uint8Array} fingerprint - Recipient fingerprint
 * @param {Number} version - The version of the PKESK packet to decrypt
 * @param {Uint8Array} [randomPayload] - Data to return on decryption error, instead of throwing
 *                                    (needed for constant-time processing in RSA and ElGamal)
 * @returns {Promise<{ sessionKey: Uint8Array, sessionKeyAlgorithm: any }>} Decrypted session key and params.
 * @throws {Error} on sensitive decryption error, unless `randomPayload` is given
 * @async
 */
export async function publicKeyDecrypt(algo, publicKeyParams, privateKeyParams, sessionKeyParams, fingerprint, version, randomSessionKey) {
  const randomPayload = randomSessionKey ?
      encodeSessionKey(version, algo, randomSessionKey.sessionKeyAlgorithm, randomSessionKey.sessionKey) :
      null;
  let decryptedData;
  let sessionKeyAlgorithm;
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt: {
      const { c } = sessionKeyParams;
      const { n, e } = publicKeyParams;
      const { d, p, q, u } = privateKeyParams;
      decryptedData = await publicKey.rsa.decrypt(c, n, e, d, p, q, u, randomPayload);
      break;
    }
    case enums.publicKey.elgamal: {
      const { c1, c2 } = sessionKeyParams;
      const p = publicKeyParams.p;
      const x = privateKeyParams.x;
      decryptedData = await publicKey.elgamal.decrypt(c1, c2, p, x, randomPayload);
      break;
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicKeyParams;
      const { d } = privateKeyParams;
      const { V, C } = sessionKeyParams;
      decryptedData = await publicKey.elliptic.ecdh.decrypt(
        oid, kdfParams, V, C.data, Q, d, fingerprint);
      break;
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const { A } = publicKeyParams;
      const { k } = privateKeyParams;
      const { ephemeralPublicKey, metadata, C } = sessionKeyParams;
      decryptedData = await publicKey.elliptic.ecdhMontgomery.decrypt(
        algo, ephemeralPublicKey, C, A, k);
      if (version === 3) {
        if (metadata.length < 2) {
          throw new Error(`No session key algorithm for PKESK v3 packet.`);
        }
        sessionKeyAlgorithm = metadata[1];
      }
      break;
    }
    default:
      throw new Error('Unknown public key encryption algorithm.');
  }
  let sessionKeyDecoded = decodeSessionKey(version, algo, decryptedData, randomSessionKey);
  if (sessionKeyAlgorithm) {
    sessionKeyDecoded.sessionKeyAlgorithm = sessionKeyAlgorithm;
  }
  return sessionKeyDecoded;
}

/**
 * Parse public key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @returns {{ read: Number, publicParams: Object }} Number of read bytes plus key parameters referenced by name.
 */
export function parsePublicKeyParams(algo, bytes) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const n = util.readMPI(bytes.subarray(read)); read += n.length + 2;
      const e = util.readMPI(bytes.subarray(read)); read += e.length + 2;
      return { read, publicParams: { n, e } };
    }
    case enums.publicKey.dsa: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, q, g, y } };
    }
    case enums.publicKey.elgamal: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, g, y } };
    }
    case enums.publicKey.ecdsa: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      let Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      Q = util.leftPad(Q, 33);
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.ecdh: {
      const oid = new OID(); read += oid.read(bytes);
      checkSupportedCurve(oid);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      const kdfParams = new KDFParams(); read += kdfParams.read(bytes.subarray(read));
      return { read: read, publicParams: { oid, Q, kdfParams } };
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const A = bytes.subarray(read, read + getCurvePayloadSize(algo)); read += A.length;
      return { read, publicParams: { A } };
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/**
 * Parse private key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @param {Object} publicParams - (ECC only) public params, needed to format some private params
 * @returns {{ read: Number, privateParams: Object }} Number of read bytes plus the key parameters referenced by name.
 */
export function parsePrivateKeyParams(algo, bytes, publicParams) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const u = util.readMPI(bytes.subarray(read)); read += u.length + 2;
      return { read, privateParams: { d, p, q, u } };
    }
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal: {
      const x = util.readMPI(bytes.subarray(read)); read += x.length + 2;
      return { read, privateParams: { x } };
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const payloadSize = getCurvePayloadSize(algo, publicParams.oid);
      let d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      d = util.leftPad(d, payloadSize);
      return { read, privateParams: { d } };
    }
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      const payloadSize = getCurvePayloadSize(algo, publicParams.oid);
      let seed = util.readMPI(bytes.subarray(read)); read += seed.length + 2;
      seed = util.leftPad(seed, payloadSize);
      return { read, privateParams: { seed } };
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const payloadSize = getCurvePayloadSize(algo);
      const seed = bytes.subarray(read, read + payloadSize); read += seed.length;
      return { read, privateParams: { seed } };
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const payloadSize = getCurvePayloadSize(algo);
      const k = bytes.subarray(read, read + payloadSize); read += k.length;
      return { read, privateParams: { k } };
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/** Returns the types comprising the encrypted session key of an algorithm
 * @param {module:enums.publicKey} algo - The key algorithm
 * @param {Uint8Array} bytes - The key material to parse
 * @param {Number} version - The PKESK version
 * @returns {Object} The session key parameters referenced by name.
 */
export function parseEncSessionKeyParams(algo, bytes, version) {
  let read = 0;
  switch (algo) {
    //   Algorithm-Specific Fields for RSA encrypted session keys:
    //       - MPI of RSA encrypted value m**e mod n.
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const c = util.readMPI(bytes.subarray(read));
      return { c };
    }

    //   Algorithm-Specific Fields for Elgamal encrypted session keys:
    //       - MPI of Elgamal value g**k mod p
    //       - MPI of Elgamal value m * y**k mod p
    case enums.publicKey.elgamal: {
      const c1 = util.readMPI(bytes.subarray(read)); read += c1.length + 2;
      const c2 = util.readMPI(bytes.subarray(read));
      return { c1, c2 };
    }
    //   Algorithm-Specific Fields for ECDH encrypted session keys:
    //       - MPI containing the ephemeral key used to establish the shared secret
    //       - ECDH Symmetric Key
    case enums.publicKey.ecdh: {
      const V = util.readMPI(bytes.subarray(read)); read += V.length + 2;
      const C = new ECDHSymkey(); C.read(bytes.subarray(read));
      return { V, C };
    }
    //   Algorithm-Specific Fields for X25519/x448 encrypted session keys:
    //       - pointSize octets representing an ephemeral public key.
    //       - A one-octet size of the following fields.
    //       - The one-octet algorithm identifier, if it was passed (in the case of a v3 PKESK packet).
    //       - The encrypted session key.
    case enums.publicKey.x25519: 
    case enums.publicKey.x448: {
      const pointSize = getCurvePayloadSize(algo);
      const ephemeralPublicKey = bytes.subarray(read, read + pointSize); read += ephemeralPublicKey.length;
      let followLength = bytes[read++];
      const metadata = version === 3 ?
        new Uint8Array([followLength--, bytes[read++]]): 
        new Uint8Array([followLength]);
      if (version === 3 && !util.isAES(metadata[1])) {
        throw new Error('Unexpected non-AES session key');
      }
      const C = bytes.subarray(read, read + followLength); read += followLength;
      return { ephemeralPublicKey, metadata, C };  
    }
    default:
      throw new UnsupportedError('Unknown public key encryption algorithm.');
  }
}

/**
 * Convert params to MPI and serializes them in the proper order
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Object} params - The key parameters indexed by name
 * @returns {Uint8Array} The array containing the MPIs.
 */
export function serializeParams(algo, params) {
  // Some algorithms do not rely on MPIs to store the binary params
  const algosWithNativeRepresentation = new Set([enums.publicKey.ed25519, enums.publicKey.x25519, enums.publicKey.ed448, enums.publicKey.x448]);
  const orderedParams = Object.keys(params).map(name => {
    const param = params[name];
    if (!util.isUint8Array(param)) return param.write();
    return algosWithNativeRepresentation.has(algo) ? param : util.uint8ArrayToMPI(param);
  });
  return util.concatUint8Array(orderedParams);
}

/**
 * Generate algorithm-specific key parameters
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Integer} bits - Bit length for RSA keys
 * @param {module:type/oid} oid - Object identifier for ECC keys
 * @returns {Promise<{ publicParams: {Object}, privateParams: {Object} }>} The parameters referenced by name.
 * @async
 */
export function generateParams(algo, bits, oid) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      return publicKey.rsa.generate(bits, 65537).then(({ n, e, d, p, q, u }) => ({
        privateParams: { d, p, q, u },
        publicParams: { n, e }
      }));
    }
    case enums.publicKey.ecdsa:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { d: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { seed: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.ecdh:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret, hash, cipher }) => ({
        privateParams: { d: secret },
        publicParams: {
          oid: new OID(oid),
          Q,
          kdfParams: new KDFParams({ hash, cipher })
        }
      }));
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      return publicKey.elliptic.eddsa.generate(algo).then(({ A, seed }) => ({
        privateParams: { seed },
        publicParams: { A }
      }));
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
      return publicKey.elliptic.ecdhMontgomery.generate(algo).then(({ A, k }) => ({
        privateParams: { k },
        publicParams: { A }
      }));
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal:
      throw new Error('Unsupported algorithm for key generation.');
    default:
      throw new Error('Unknown public key algorithm.');
  }
}

/**
 * Validate algorithm-specific key parameters
 * @param {module:enums.publicKey} algo - The public key algorithm
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Object} privateParams - Algorithm-specific private key parameters
 * @returns {Promise<Boolean>} Whether the parameters are valid.
 * @async
 */
export async function validateParams(algo, publicParams, privateParams) {
  if (!publicParams || !privateParams) {
    throw new Error('Missing key parameters');
  }
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const { d, p, q, u } = privateParams;
      return publicKey.rsa.validateParams(n, e, d, p, q, u);
    }
    case enums.publicKey.dsa: {
      const { p, q, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.dsa.validateParams(p, q, g, y, x);
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.elgamal.validateParams(p, g, y, x);
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const algoModule = publicKey.elliptic[enums.read(enums.publicKey, algo)];
      const { oid, Q } = publicParams;
      const { d } = privateParams;
      return algoModule.validateParams(oid, Q, d);
    }
    case enums.publicKey.eddsa:
    case enums.publicKey.ed25519Legacy: {
      const { Q, oid } = publicParams;
      const { seed } = privateParams;
      return publicKey.elliptic.eddsaLegacy.validateParams(oid, Q, seed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const { A } = publicParams;
      const { seed } = privateParams;
      return publicKey.elliptic.eddsa.validateParams(algo, A, seed);
    }
    case enums.publicKey.x25519:
    case enums.publicKey.x448: {
      const { A } = publicParams;
      const { k } = privateParams;
      return publicKey.elliptic.ecdhMontgomery.validateParams(algo, A, k);
    }
    default:
      throw new Error('Unknown public key algorithm.');
  }
}

/**
 * Generates a random byte prefix for the specified algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} algo - Symmetric encryption algorithm
 * @returns {Promise<Uint8Array>} Random bytes with length equal to the block size of the cipher, plus the last two bytes repeated.
 * @async
 */
export async function getPrefixRandom(algo) {
  const { blockSize } = getCipher(algo);
  const prefixrandom = await getRandomBytes(blockSize);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  return util.concat([prefixrandom, repeat]);
}

/**
 * Generating a session key for the specified symmetric algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric} algo - Symmetric encryption algorithm
 * @returns {Uint8Array} Random bytes as a string to be used as a key.
 */
export function generateSessionKey(algo) {
  const { keySize } = getCipher(algo);
  return getRandomBytes(keySize);
}

/**
 * Get implementation of the given AEAD mode
 * @param {enums.aead} algo
 * @returns {Object}
 * @throws {Error} on invalid algo
 */
export function getAEADMode(algo) {
  const algoName = enums.read(enums.aead, algo);
  return mode[algoName];
}

export { getCipher };

/**
 * Check whether the given curve OID is supported
 * @param {module:type/oid} oid - EC object identifier
 * @throws {UnsupportedError} if curve is not supported
 */
function checkSupportedCurve(oid) {
  try {
    oid.getName();
  } catch (e) {
    throw new UnsupportedError('Unknown curve OID');
  }
}

/**
 * Get encoded secret size for a given elliptic algo
 * @param {module:enums.publicKey} algo - alrogithm identifier
 * @param {module:type/oid} [oid] - curve OID if needed by algo
 */
export function getCurvePayloadSize(algo, oid) {
  switch (algo) {
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh:
    case enums.publicKey.ed25519Legacy:
      return new publicKey.elliptic.CurveWithOID(oid).payloadSize;
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448:
      return publicKey.elliptic.eddsa.getPayloadSize(algo);
    case enums.publicKey.x25519:
    case enums.publicKey.x448:
      return publicKey.elliptic.ecdhMontgomery.getPayloadSize(algo);
    default:
      throw new Error('Unknown elliptic algo'); 
  }
}

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
