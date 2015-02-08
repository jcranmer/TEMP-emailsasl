/**
 * This file contains a polyfill for the WebCrypto API for use on Node.js. Only
 * the functions that are needed to implement CRAM-MD5 and SCRAM are
 * implemented, since I needed a polyfill but none existed. This supports the
 * following operations:
 * * importKey: raw format only.
 * * sign: HMAC
 * * deriveBits: PBKDF2
 * * deriveKey: PBKDF2 (for HMAC keys only)
 * * digest: MD5 (not in WebCrypto), SHA-{1,256,384,512}
 *
 * Error handling is likely to work poorly in this polyfill.
 *
 * For documentation of how these values are supposed to work, go see
 * <http://www.w3.org/TR/WebCryptoAPI>.
 * @module sasl-crypto
 * @private
 */

var crypto = require('crypto');
var webcrypto = {};

webcrypto.getRandomValues = function (array) {
  var random = crypto.randomBytes(array.length);
  for (var i = 0; i < array.length; i++)
    array[i] = random[i];
  return array;
};

var algMap = {
  'MD5': "md5",
  'SHA-1': "sha1",
  'SHA-256': "sha256",
  'SHA-384': "sha384",
  'SHA-512': "sha512",
};

var subtle = {};
subtle.digest = function (algorithm, data) {
  return new Promise(function (resolve, reject) {
    if (!algMap[algorithm]) {
      reject(new Error("Unknown algorithm " + algorithm));
      return;
    }
    var hash = crypto.createHash(algMap[algorithm]);
    hash.update(data);
    resolve(hash.digest());
  });
};

subtle.importKey = function (format, keyData, algorithm, extractable, usages) {
  return new Promise(function (resolve, reject) {
    if (format !== "raw") {
      throw new Error("This polyfill only supports raw key import");
    }
    resolve({
      type: "secret",
      extractable: extractable,
      usages: usages,
      algorithm: algorithm,
      _data: keyData
    });
  });
};

subtle.sign = function (algorithm, key, data) {
  return new Promise(function (resolve, reject) {
    if (key.usages.indexOf('sign') == -1 || key.algorithm != algorithm)
      throw new Error("Cannot use this algorithm with this key");
    if (algorithm.name == "HMAC") {
      var hmac = crypto.createHmac(algMap[algorithm.hash], key._data);
      hmac.update(data);
      resolve(hmac.digest());
    } else {
      reject(new Error("Unknown algorithm " + algorithm.name));
    }
  });
};

function deriveBits(algorithm, key, length, usage) {
  return new Promise(function (resolve, reject) {
    if (key.usages.indexOf(usage) == -1 || key.algorithm != algorithm)
      throw new Error("Cannot use this algorithm with this key");
    if (algorithm.name != "PBKDF2")
      throw new Error("Unknown algorithm " + algorithm.name);
    var hashName = algMap[algorithm.hash];
    crypto.pbkdf2(key._data, algorithm.salt, algorithm.iterations, length,
      hashName, function (err, derived) {
        if (err)
          reject(err);
        else
          resolve(derived);
    });
  });
}

subtle.deriveBits = function (algorithm, key, length) {
  return deriveBits(algorithm, key, length, 'deriveBits');
};

subtle.deriveKey = function (algorithm, key, derivedAlgo, extractable, usages) {
  var length = crypto.createHash(algMap[derivedAlgo.hash]).digest().length;
  return deriveBits(algorithm, key, length, 'deriveKey').then(function (data) {
    return subtle.importKey("raw", data, derivedAlgo, extractable, usages);
  });
};

webcrypto.subtle = subtle;
module.exports = webcrypto;
