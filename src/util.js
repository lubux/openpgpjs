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

/* eslint-disable no-console */

/**
 * This object contains utility functions
 * @requires email-addresses
 * @requires web-stream-tools
 * @requires config
 * @requires encoding/base64
 * @module util
 */

import stream from 'web-stream-tools';
import config from './config';
import util from './util'; // re-import module to access util functions
import { getBigInteger } from './biginteger';

export default {
  isString: function(data) {
    return typeof data === 'string' || String.prototype.isPrototypeOf(data);
  },

  isArray: function(data) {
    return Array.prototype.isPrototypeOf(data);
  },

  isBigInteger: function(data) {
    return data !== null && typeof data === 'object' && data.value &&
      // eslint-disable-next-line valid-typeof
      (typeof data.value === 'bigint' || this.isBN(data.value));
  },

  isBN: function(data) {
    return data !== null && typeof data === 'object' &&
      (data.constructor.name === 'BN' ||
        (data.constructor.wordSize === 26 && Array.isArray(data.words))); // taken from BN.isBN()
  },

  isUint8Array: stream.isUint8Array,

  isStream: stream.isStream,

  /**
   * Convert MessagePorts back to ReadableStreams
   * @param  {Object} obj
   * @returns {Object}
   */
  restoreStreams: function(obj, streaming) {
    if (Object.prototype.toString.call(obj) === '[object MessagePort]') {
      return new (streaming === 'web' ? globalThis.ReadableStream : stream.ReadableStream)({
        pull(controller) {
          return new Promise(resolve => {
            obj.onmessage = evt => {
              const { done, value, error } = evt.data;
              if (error) {
                controller.error(new Error(error));
              } else if (!done) {
                controller.enqueue(value);
              } else {
                controller.close();
              }
              resolve();
            };
            obj.postMessage({ action: 'read' });
          });
        },
        cancel() {
          return new Promise(resolve => {
            obj.onmessage = resolve;
            obj.postMessage({ action: 'cancel' });
          });
        }
      }, { highWaterMark: 0 });
    }
    if (Object.prototype.isPrototypeOf(obj) && !Uint8Array.prototype.isPrototypeOf(obj)) {
      Object.entries(obj).forEach(([key, value]) => { // recursively search all children
        obj[key] = util.restoreStreams(value, streaming);
      });
    }
    return obj;
  },

  readNumber: function (bytes) {
    let n = 0;
    for (let i = 0; i < bytes.length; i++) {
      n += (256 ** i) * bytes[bytes.length - 1 - i];
    }
    return n;
  },

  writeNumber: function (n, bytes) {
    const b = new Uint8Array(bytes);
    for (let i = 0; i < bytes; i++) {
      b[i] = (n >> (8 * (bytes - i - 1))) & 0xFF;
    }

    return b;
  },

  readDate: function (bytes) {
    const n = util.readNumber(bytes);
    const d = new Date(n * 1000);
    return d;
  },

  writeDate: function (time) {
    const numeric = Math.floor(time.getTime() / 1000);

    return util.writeNumber(numeric, 4);
  },

  normalizeDate: function (time = Date.now()) {
    return time === null || time === Infinity ? time : new Date(Math.floor(+time / 1000) * 1000);
  },

  /**
   * Create hex string from a binary
   * @param {String} str String to convert
   * @returns {String} String containing the hexadecimal values
   */
  strToHex: function (str) {
    if (str === null) {
      return "";
    }
    const r = [];
    const e = str.length;
    let c = 0;
    let h;
    while (c < e) {
      h = str.charCodeAt(c++).toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Create binary string from a hex encoded string
   * @param {String} str Hex string to convert
   * @returns {String}
   */
  hexToStr: function (hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
      str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
  },

  /**
   * Read one MPI from bytes in input
   * @param {Uint8Array} bytes  input data to parse
   * @returns {Uint8Array} parsed MPI
   */
  readMPI: function (bytes) {
    const bits = (bytes[0] << 8) | bytes[1];
    const bytelen = (bits + 7) >>> 3;
    return bytes.subarray(2, 2 + bytelen);
  },

  /**
   * Left-pad Uint8Array to length by adding 0x0 bytes
   * @param {Uint8Array} bytes      data to pad
   * @param {Number}     length     padded length
   * @return {Uint8Array} padded bytes
   */
  leftPad(bytes, length) {
    const padded = new Uint8Array(length);
    const offset = length - bytes.length;
    padded.set(bytes, offset);
    return padded;
  },

  /**
   * Convert a Uint8Array to an MPI-formatted Uint8Array.
   * @param {Uint8Array} bin An array of 8-bit integers to convert
   * @returns {Uint8Array} MPI-formatted Uint8Array
   */
  uint8ArrayToMpi: function (bin) {
    let i; // index of leading non-zero byte
    for (i = 0; i < bin.length; i++) if (bin[i] !== 0) break;
    if (i === bin.length) {
      throw new Error('Zero MPI');
    }
    const stripped = bin.subarray(i);
    const size = (stripped.length - 1) * 8 + util.nbits(stripped[0]);
    const prefix = Uint8Array.from([(size & 0xFF00) >> 8, size & 0xFF]);
    return util.concatUint8Array([prefix, stripped]);
  },

  /**
   * Convert a hex string to an array of 8-bit integers
   * @param {String} hex  A hex string to convert
   * @returns {Uint8Array} An array of 8-bit integers
   */
  hexToUint8Array: function (hex) {
    const result = new Uint8Array(hex.length >> 1);
    for (let k = 0; k < hex.length >> 1; k++) {
      result[k] = parseInt(hex.substr(k << 1, 2), 16);
    }
    return result;
  },

  /**
   * Convert an array of 8-bit integers to a hex string
   * @param {Uint8Array} bytes Array of 8-bit integers to convert
   * @returns {String} Hexadecimal representation of the array
   */
  uint8ArrayToHex: function (bytes) {
    const r = [];
    const e = bytes.length;
    let c = 0;
    let h;
    while (c < e) {
      h = bytes[c++].toString(16);
      while (h.length < 2) {
        h = "0" + h;
      }
      r.push("" + h);
    }
    return r.join('');
  },

  /**
   * Convert a string to an array of 8-bit integers
   * @param {String} str String to convert
   * @returns {Uint8Array} An array of 8-bit integers
   */
  strToUint8Array: function (str) {
    return stream.transform(str, str => {
      if (!util.isString(str)) {
        throw new Error('strToUint8Array: Data must be in the form of a string');
      }

      const result = new Uint8Array(str.length);
      for (let i = 0; i < str.length; i++) {
        result[i] = str.charCodeAt(i);
      }
      return result;
    });
  },

  /**
   * Convert an array of 8-bit integers to a string
   * @param {Uint8Array} bytes An array of 8-bit integers to convert
   * @returns {String} String representation of the array
   */
  uint8ArrayToStr: function (bytes) {
    bytes = new Uint8Array(bytes);
    const result = [];
    const bs = 1 << 14;
    const j = bytes.length;

    for (let i = 0; i < j; i += bs) {
      result.push(String.fromCharCode.apply(String, bytes.subarray(i, i + bs < j ? i + bs : j)));
    }
    return result.join('');
  },

  /**
   * Convert a native javascript string to a Uint8Array of utf8 bytes
   * @param {String|ReadableStream} str The string to convert
   * @returns {Uint8Array|ReadableStream} A valid squence of utf8 bytes
   */
  encodeUtf8: function (str) {
    const encoder = new TextEncoder('utf-8');
    // eslint-disable-next-line no-inner-declarations
    function process(value, lastChunk = false) {
      return encoder.encode(value, { stream: !lastChunk });
    }
    return stream.transform(str, process, () => process('', true));
  },

  /**
   * Convert a Uint8Array of utf8 bytes to a native javascript string
   * @param {Uint8Array|ReadableStream} utf8 A valid squence of utf8 bytes
   * @returns {String|ReadableStream} A native javascript string
   */
  decodeUtf8: function (utf8) {
    const decoder = new TextDecoder('utf-8');
    // eslint-disable-next-line no-inner-declarations
    function process(value, lastChunk = false) {
      return decoder.decode(value, { stream: !lastChunk });
    }
    return stream.transform(utf8, process, () => process(new Uint8Array(), true));
  },

  /**
   * Concat a list of Uint8Arrays, Strings or Streams
   * The caller must not mix Uint8Arrays with Strings, but may mix Streams with non-Streams.
   * @param {Array<Uint8Array|String|ReadableStream>} Array of Uint8Arrays/Strings/Streams to concatenate
   * @returns {Uint8Array|String|ReadableStream} Concatenated array
   */
  concat: stream.concat,

  /**
   * Concat Uint8Arrays
   * @param {Array<Uint8Array>} Array of Uint8Arrays to concatenate
   * @returns {Uint8Array} Concatenated array
   */
  concatUint8Array: stream.concatUint8Array,

  /**
   * Check Uint8Array equality
   * @param {Uint8Array} array1 first array
   * @param {Uint8Array} array2 second array
   * @returns {Boolean} equality
   */
  equalsUint8Array: function (array1, array2) {
    if (!util.isUint8Array(array1) || !util.isUint8Array(array2)) {
      throw new Error('Data must be in the form of a Uint8Array');
    }

    if (array1.length !== array2.length) {
      return false;
    }

    for (let i = 0; i < array1.length; i++) {
      if (array1[i] !== array2[i]) {
        return false;
      }
    }
    return true;
  },

  /**
   * Calculates a 16bit sum of a Uint8Array by adding each character
   * codes modulus 65535
   * @param {Uint8Array} Uint8Array to create a sum of
   * @returns {Uint8Array} 2 bytes containing the sum of all charcodes % 65535
   */
  writeChecksum: function (text) {
    let s = 0;
    for (let i = 0; i < text.length; i++) {
      s = (s + text[i]) & 0xFFFF;
    }
    return util.writeNumber(s, 2);
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  printDebug: function (str) {
    if (config.debug) {
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call Uint8ArrayToHex iff necessary.
   * @param {String} str String of the debug message
   */
  printDebugHexArrayDump: function (str, arrToHex) {
    if (config.debug) {
      str += ': ' + util.uint8ArrayToHex(arrToHex);
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug message. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * Different than print_debug because will call strToHex iff necessary.
   * @param {String} str String of the debug message
   */
  printDebugHexStrDump: function (str, strToHex) {
    if (config.debug) {
      str += util.strToHex(strToHex);
      console.log(str);
    }
  },

  /**
   * Helper function to print a debug error. Debug
   * messages are only printed if
   * @link module:config/config.debug is set to true.
   * @param {String} str String of the debug message
   */
  printDebugError: function (error) {
    if (config.debug) {
      console.error(error);
    }
  },

  /**
   * Read a stream to the end and print it to the console when it's closed.
   * @param {String} str String of the debug message
   * @param {ReadableStream|Uint8array|String} input Stream to print
   * @param {Function} concat Function to concatenate chunks of the stream (defaults to util.concat).
   */
  printEntireStream: function (str, input, concat) {
    stream.readToEnd(stream.clone(input), concat).then(result => {
      console.log(str + ': ', result);
    });
  },

  // returns bit length of the integer x
  nbits: function (x) {
    let r = 1;
    let t = x >>> 16;
    if (t !== 0) {
      x = t;
      r += 16;
    }
    t = x >> 8;
    if (t !== 0) {
      x = t;
      r += 8;
    }
    t = x >> 4;
    if (t !== 0) {
      x = t;
      r += 4;
    }
    t = x >> 2;
    if (t !== 0) {
      x = t;
      r += 2;
    }
    t = x >> 1;
    if (t !== 0) {
      x = t;
      r += 1;
    }
    return r;
  },

  /**
   * If S[1] == 0, then double(S) == (S[2..128] || 0);
   * otherwise, double(S) == (S[2..128] || 0) xor
   * (zeros(120) || 10000111).
   *
   * Both OCB and EAX (through CMAC) require this function to be constant-time.
   *
   * @param {Uint8Array} data
   */
  double: function(data) {
    const double_var = new Uint8Array(data.length);
    const last = data.length - 1;
    for (let i = 0; i < last; i++) {
      double_var[i] = (data[i] << 1) ^ (data[i + 1] >> 7);
    }
    double_var[last] = (data[last] << 1) ^ ((data[0] >> 7) * 0x87);
    return double_var;
  },

  /**
   * Shift a Uint8Array to the right by n bits
   * @param {Uint8Array} array The array to shift
   * @param {Integer} bits Amount of bits to shift (MUST be smaller
   * than 8)
   * @returns {String} Resulting array.
   */
  shiftRight: function (array, bits) {
    if (bits) {
      for (let i = array.length - 1; i >= 0; i--) {
        array[i] >>= bits;
        if (i > 0) {
          array[i] |= (array[i - 1] << (8 - bits));
        }
      }
    }
    return array;
  },

  /**
   * Get native Web Cryptography api, only the current version of the spec.
   * The default configuration is to use the api when available. But it can
   * be deactivated with config.useNative
   * @returns {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCrypto: function() {
    if (!config.useNative) {
      return;
    }

    return typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle;
  },

  /**
   * Get native Web Cryptography api for all browsers, including legacy
   * implementations of the spec e.g IE11 and Safari 8/9. The default
   * configuration is to use the api when available. But it can be deactivated
   * with config.useNative
   * @returns {Object}   The SubtleCrypto api or 'undefined'
   */
  getWebCryptoAll: function() {
    if (!config.useNative) {
      return;
    }

    if (typeof globalThis !== 'undefined') {
      if (globalThis.crypto) {
        return globalThis.crypto.subtle || globalThis.crypto.webkitSubtle;
      }
      if (globalThis.msCrypto) {
        return globalThis.msCrypto.subtle;
      }
    }
  },

  /**
   * Detect Node.js runtime.
   */
  detectNode: function() {
    return typeof globalThis.process === 'object' &&
      typeof globalThis.process.versions === 'object';
  },

  /**
   * Detect native BigInt support
   */
  detectBigInt: () => typeof BigInt !== 'undefined',

  /**
   * Get BigInteger class
   * It wraps the native BigInt type if it's available
   * Otherwise it relies on bn.js
   * @returns {BigInteger}
   * @async
   */
  getBigInteger,

  /**
   * Get native Node.js crypto api. The default configuration is to use
   * the api when available. But it can also be deactivated with config.useNative
   * @returns {Object}   The crypto module or 'undefined'
   */
  getNodeCrypto: function() {
    if (!config.useNative) {
      return;
    }

    return require('crypto');
  },

  getNodeZlib: function() {
    if (!config.useNative) {
      return;
    }

    return require('zlib');
  },

  /**
   * Get native Node.js Buffer constructor. This should be used since
   * Buffer is not available under browserify.
   * @returns {Function}   The Buffer constructor or 'undefined'
   */
  getNodeBuffer: function() {
    return (require('buffer') || {}).Buffer;
  },

  getNodeStream: function() {
    return (require('stream') || {}).Readable;
  },

  getHardwareConcurrency: function() {
    if (util.detectNode()) {
      const os = require('os');
      return os.cpus().length;
    }

    return navigator.hardwareConcurrency || 1;
  },

  isEmailAddress: function(data) {
    if (!util.isString(data)) {
      return false;
    }
    const re = /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+([a-zA-Z]{2,}|xn--[a-zA-Z\-0-9]+)))$/;
    return re.test(data);
  },

  /**
   * Normalize line endings to <CR><LF>
   * Support any encoding where CR=0x0D, LF=0x0A
   */
  canonicalizeEOL: function(data) {
    const CR = 13;
    const LF = 10;
    let carryOverCR = false;

    return stream.transform(data, bytes => {
      if (carryOverCR) {
        bytes = util.concatUint8Array([new Uint8Array([CR]), bytes]);
      }

      if (bytes[bytes.length - 1] === CR) {
        carryOverCR = true;
        bytes = bytes.subarray(0, -1);
      } else {
        carryOverCR = false;
      }

      let index;
      const indices = [];
      for (let i = 0; ; i = index) {
        index = bytes.indexOf(LF, i) + 1;
        if (index) {
          if (bytes[index - 2] !== CR) indices.push(index);
        } else {
          break;
        }
      }
      if (!indices.length) {
        return bytes;
      }

      const normalized = new Uint8Array(bytes.length + indices.length);
      let j = 0;
      for (let i = 0; i < indices.length; i++) {
        const sub = bytes.subarray(indices[i - 1] || 0, indices[i]);
        normalized.set(sub, j);
        j += sub.length;
        normalized[j - 1] = CR;
        normalized[j] = LF;
        j++;
      }
      normalized.set(bytes.subarray(indices[indices.length - 1] || 0), j);
      return normalized;
    }, () => (carryOverCR ? new Uint8Array([CR]) : undefined));
  },

  /**
   * Convert line endings from canonicalized <CR><LF> to native <LF>
   * Support any encoding where CR=0x0D, LF=0x0A
   */
  nativeEOL: function(data) {
    const CR = 13;
    const LF = 10;
    let carryOverCR = false;

    return stream.transform(data, bytes => {
      if (carryOverCR && bytes[0] !== LF) {
        bytes = util.concatUint8Array([new Uint8Array([CR]), bytes]);
      } else {
        bytes = new Uint8Array(bytes); // Don't mutate passed bytes
      }

      if (bytes[bytes.length - 1] === CR) {
        carryOverCR = true;
        bytes = bytes.subarray(0, -1);
      } else {
        carryOverCR = false;
      }

      let index;
      let j = 0;
      for (let i = 0; i !== bytes.length; i = index) {
        index = bytes.indexOf(CR, i) + 1;
        if (!index) index = bytes.length;
        const last = index - (bytes[index] === LF ? 1 : 0);
        if (i) bytes.copyWithin(j, i, last);
        j += last - i;
      }
      return bytes.subarray(0, j);
    }, () => (carryOverCR ? new Uint8Array([CR]) : undefined));
  },

  /**
   * Remove trailing spaces and tabs from each line
   */
  removeTrailingSpaces: function(text) {
    return text.split('\n').map(line => {
      let i = line.length - 1;
      for (; i >= 0 && (line[i] === ' ' || line[i] === '\t'); i--);
      return line.substr(0, i + 1);
    }).join('\n');
  },

  /**
   * Encode input buffer using Z-Base32 encoding.
   * See: https://tools.ietf.org/html/rfc6189#section-5.1.6
   *
   * @param {Uint8Array} data The binary data to encode
   * @returns {String} Binary data encoded using Z-Base32
   */
  encodeZBase32: function(data) {
    if (data.length === 0) {
      return "";
    }
    const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
    const SHIFT = 5;
    const MASK = 31;
    let buffer = data[0];
    let index = 1;
    let bitsLeft = 8;
    let result = '';
    while (bitsLeft > 0 || index < data.length) {
      if (bitsLeft < SHIFT) {
        if (index < data.length) {
          buffer <<= 8;
          buffer |= data[index++] & 0xff;
          bitsLeft += 8;
        } else {
          const pad = SHIFT - bitsLeft;
          buffer <<= pad;
          bitsLeft += pad;
        }
      }
      bitsLeft -= SHIFT;
      result += ALPHABET[MASK & (buffer >> bitsLeft)];
    }
    return result;
  },

  wrapError: function(message, error) {
    if (!error) {
      return new Error(message);
    }

    // update error message
    try {
      error.message = message + ': ' + error.message;
    } catch (e) {}

    return error;
  }
};
