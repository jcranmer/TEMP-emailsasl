(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define([], factory);
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory();
  } else {
    // Browser globals (root is window)
    root.saslUtils = factory();
  }
}(this, function () {

/**
 * Run the result of SASLprep (RFC 4013 as of this writing) on the input string.
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
 */
function stringToBase64UTF8(str) {
  return new Buffer(str, "UTF-8").toString("base64");
}

/**
 * Convert a Unicode string into a Uint8Array of its UTF-8-encoded bytes.
 */
function stringToArrayBuffer(str) {
  return new Uint8Array(new Buffer(str, "utf-8"));
}

/**
 * Convert a Uint8Array into a string containing the base64 representation of
 * its contents.
 */
function arrayBufferToBase64(buf) {
  return new Buffer(buf).toString("base64");
}

/**
 * Convert a string containing base64-encoded data into a Uint8Array containing
 * that data.
 */
function base64ToArrayBuffer(str) {
  return new Uint8Array(new Buffer(str, "base64"));
}

/**
 * Convert a string containing base64-encoded data into a Uint8Array containing
 * that data.
 */
function base64ToBinaryString(str) {
  return new Buffer(str, "base64").toString();
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
