/**
 * This module contains a bunch of utilities for SASL implementers, partially
 * to help bridge differences between Node.js and web browsers.
 * @module sasl-utils
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], function () { return factory(TextEncoder, btoa, atob); });
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    function TextEncoder(charset) {
      this.encode = function (s) { return new Buffer(s, "utf-8"); };
    }
    function btoa(str) {
      return new Buffer(str, "binary").toString("base64");
    }
    function atob(str) {
      return new Buffer(str, "base64").toString("binary");
    }
    module.exports = factory(TextEncoder, btoa, atob);
  } else {
    // Browser globals (root is window)
    root.saslUtils = factory(root.TextEncoder, btoa, atob);
  }
}(this, function (TextEncoder, btoa, atob) {

/**
 * Run the result of SASLprep (RFC 4013 as of this writing) on the input string.
 *
 * @param {String} str The string to be prepared (e.g., a username).
 * @returns {String}   The result of SASLprep.
 * @alias module:sasl-utils.saslPrep
 */
function saslPrep(str) {
  // If you don't want to go running off to the RFC, here's the basic rules on
  // SASLprep and Stringprep. Stringprep declares mapping, normalization,
  // prohibition, and bidi check phases, with the actual rules for each defined
  // by profile (in this case, SASLprep). Since we're not storing strings, we're
  // only querying them (in Stringprep's parlance), we don't have to error out
  // on unassigned code points.
  // This code is being even more liberal and ignoring the last two phases: all
  // they do is reject strings, not change them, and support for querying Bidi
  // properties in JS is more annoying than its worth.

  // Table C.1.2 (Non-ASCII space characters) get mapped to a space
  str = str.replace(/[\u00a0\u1680\u2000-\u200B\u202f\u205f\u3000]/g, " ");
  // Table B.1 (Commonly mapped to nothing) get removed
  str = str.replace(
    // Note: \u200b is in both lists... it gets removed by the above.
    /[\u00ad\u034f\u1806\u180b-\u180d\u200c\u200d\u2060\ufe00-\ufe0f\ufeff]/g,
    "");

  // Normalization step: normalize according to KC.
  return str.normalize("NFKC");
}

/**
 * Convert a Unicode string into the base64 representation of its UTF-8-encoded
 * bytes.
 *
 * @param {String} str   The string to encode.
 * @returns {Uint8Array} The base64-encoded array.
 * @alias module:sasl-utils.stringToBase64UTF8
 */
function stringToBase64UTF8(str) {
  return arrayBufferToBase64(stringToArrayBuffer(str));
}

/**
 * Convert a Unicode string into a Uint8Array of its UTF-8-encoded bytes.
 *
 * @param {String} str   The string to be converted.
 * @returns {Uint8Array} The resulting array buffer.
 * @alias module:sasl-utils.stringToArrayBuffer
 */
function stringToArrayBuffer(str) {
  return new TextEncoder("UTF-8").encode(str);
}

/**
 * Convert a Uint8Array into a string containing the base64 representation of
 * its contents.
 *
 * @param {Uint8Array} buf The buffer to be encoded.
 * @returns {String}       The resulting base64-encoded string.
 * @alias module:sasl-utils.arrayBufferToBase64
 */
function arrayBufferToBase64(buf) {
  var str = '';
  for (var i = 0; i < buf.length; i++)
    str += String.fromCharCode(buf[i]);
  return btoa(str);
}

/**
 * Convert a string containing base64-encoded data into a Uint8Array containing
 * that data.
 *
 * @param {String} str   The base64-encoded string.
 * @returns {Uint8Array} The decoded array buffer.
 * @alias module:sasl-utils.base64ToArrayBuffer
 */
function base64ToArrayBuffer(str) {
  str = atob(str);
  var buf = new Uint8Array(str.length);
  for (var i = 0; i < str.length; i++)
    buf[i] = str.charCodeAt(i);
  return buf;
}

/**
 * Convert a string containing base64-encoded data into a Uint8Array containing
 * that data.
 *
 * @param {String} str The base64-encoded string.
 * @returns {String}   The resulting base64-decoded string.
 * @alias module:sasl-utils.base64ToBinaryString
 */
function base64ToBinaryString(str) {
  return atob(str);
}

return {
  arrayBufferToBase64: arrayBufferToBase64,
  base64ToArrayBuffer: base64ToArrayBuffer,
  base64ToBinaryString: base64ToBinaryString,
  saslPrep: saslPrep,
  stringToArrayBuffer: stringToArrayBuffer,
  stringToBase64UTF8: stringToBase64UTF8,
};
}));
