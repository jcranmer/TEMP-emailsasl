/**
 * A library of challenge-response SASL mechanisms. These are split out from the
 * main module, as these require more advanced crypto support.
 * @module sasl-cram
 * @private
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['./sasl-utils'], function (saslUtils) {
      return factory(saslUtils, crypto);
    });
  } else if (typeof exports === 'object') {
    module.exports = factory(require('./sasl-utils'), require('./sasl-crypto-polyfill'));
  } else {
    root.saslCram = factory(root.saslUtils, root.crypto);
  }
}(this, function (saslUtils, crypto) {
"use strict";

const hexString = "0123456789abcdef";
const hexBytes = [];
for (let i = 0; i < 256; i++)
  hexBytes[i] = hexString[Math.trunc(i / 16)] + hexString[i % 16];

/**
 * CRAM-MD5 SASL mechanism -- see RFC 2195 for details.
 * @private
 */
class CramMD5Module {
  constructor(server, hostname, options) {
    this.user = options.user;
    this.pass = options.pass;
  }

  isValid() {
    return this.user && this.pass;
  }

  *executeSteps(initChallenge) {
    let hmacAlgorithm = {
      name: "HMAC",
      hash: "MD5",
      length: 128
    };
    let result = crypto.subtle.importKey("raw",
      saslUtils.stringToArrayBuffer(saslUtils.saslPrep(this.pass)),
      hmacAlgorithm, false, ['sign']
    ).then(function (hmacKey) {
      return crypto.subtle.sign(hmacAlgorithm, hmacKey,
        saslUtils.base64ToArrayBuffer(initChallenge));
    }).then((function (result) {
      let hexStr = Array.from(result).map(val => hexBytes[val]).join('');
      return saslUtils.stringToBase64UTF8(
        saslUtils.saslPrep(this.user) + " " + hexStr);
    }).bind(this));

    yield result;
  }
}
CramMD5Module.isClientFirst = false;

/**
 * SCRAM SASL mechanism family -- see RFC 5802 for details. This is actually a
 * family of possible mechanisms (the complete list may be found at
 * <http://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml>).
 * @private
 */

class ScramModule {
  constructor(hashName, hashLength, options) {
    this._hashName = hashName;
    this._hashLength = hashLength;
    this._hmacAlgorithm = {
      name: "HMAC",
      hash: hashName,
      length: hashLength * 8,
    };

    this.user = options.user;
    this.pass = options.pass;

    // Create the nonce
    this.nonce = saslUtils.arrayBufferToBase64(
      crypto.getRandomValues(new Uint8Array(hashLength)));
  }

  isValid() {
    return this.user && this.pass;
  }

  *executeSteps() {
    let user = saslUtils.saslPrep(this.user)
                        .replace(',', "=2C")
                        .replace('=', "=3D");
    let gs2Header = 'n,,';
    let clientFirst = 'n=' + user + ',r=' + this.nonce;
    let response = yield saslUtils.stringToBase64UTF8(gs2Header + clientFirst);

    // Parse the server response
    let serverFirst = saslUtils.base64ToBinaryString(response);
    response = serverFirst.split(',');
    if (response[0].substring(0, 2) == 'm=')
      response.shift();
    if (response[0].substring(0, 2) != 'r=')
      throw new Error("Malformed server response");
    let servernonce = response[0].substring(2);
    if (response[1].substring(0, 2) != 's=')
      throw new Error("Malformed server response");
    let salt = saslUtils.base64ToArrayBuffer(response[1].substring(2));
    if (response[2].substring(0, 2) != 'i=')
      throw new Error("Malformed server response");
    let iterCount = parseInt(response[2].substring(2));

    let clientFinal = 'c=' + saslUtils.stringToBase64UTF8(gs2Header) + ',r=' +
      servernonce;
    let authMessage = [clientFirst, serverFirst, clientFinal].join(',');

    // Compute the ClientProof variable
    // SaltedPassword := Hi(Normalize(password), salt, i)
    let pbkdfAlgorithm = {
      name: "PBKDF2",
      hash: this._hashName,
      salt: salt,
      iterations: iterCount
    };
    let saltedPassword = crypto.subtle.importKey("raw",
      saslUtils.stringToArrayBuffer(saslUtils.saslPrep(this.pass)),
      pbkdfAlgorithm, false, ['deriveKey']).then((passwordKey) => {
        this._hmacAlgorithm.length = 160;
        return crypto.subtle.deriveKey(pbkdfAlgorithm, passwordKey,
          this._hmacAlgorithm, false, ['sign']);
    });

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    let clientKey = saltedPassword.then((saltedPassword) => {
      return crypto.subtle.sign(this._hmacAlgorithm, saltedPassword,
        saslUtils.stringToArrayBuffer("Client Key"));
    });

    // StoredKey := H(ClientKey)
    let storedKey = clientKey.then((clientKey) => {
      return crypto.subtle.digest(this._hashName, clientKey);
    }).then((storedKey) => {
      return crypto.subtle.importKey("raw", storedKey, this._hmacAlgorithm, false,
        ['sign']);
    });

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    let clientSignature = storedKey.then((storedKey) => {
      return crypto.subtle.sign(this._hmacAlgorithm, storedKey,
        saslUtils.stringToArrayBuffer(authMessage));
    });

    // ClientProof := ClientKey XOR ClientSignature
    let clientProof = Promise.all([clientKey, clientSignature]).then(
        (values) => {
      let clientKey = new Uint8Array(values[0]);
      let clientSignature = new Uint8Array(values[1]);
      let clientProof = new Uint8Array(clientSignature.length);
      for (let i = 0; i < clientProof.length; i++)
        clientProof[i] = clientKey[i] ^ clientSignature[i];
      return clientProof;
    });

    // Now we can output the final message.
    let serverFinal = yield clientProof.then((clientProof) => {
      return saslUtils.stringToBase64UTF8(clientFinal + ',p=' +
          saslUtils.arrayBufferToBase64(clientProof));
    });

    // Verify the server response.
    // ServerKey := HMAC(SaltedPassword, "Server Key")
    let serverKey = saltedPassword.then((saltedPassword) => {
      return crypto.subtle.sign(this._hmacAlgorithm, saltedPassword,
        saslUtils.stringToArrayBuffer("Server Key"));
    }).then((serverKey) => {
      return crypto.subtle.importKey("raw", serverKey, this._hmacAlgorithm, false,
          ['sign']);
    });

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    let serverSignature = serverKey.then((serverKey) => {
      return crypto.subtle.sign(this._hmacAlgorithm, serverKey,
        saslUtils.stringToArrayBuffer(authMessage));
    });

    let verificationPromise = serverSignature.then((serverSignature) => {
      serverSignature = new Uint8Array(serverSignature);
      let expected = 'v=' + saslUtils.arrayBufferToBase64(serverSignature);
      if (saslUtils.stringToBase64UTF8(expected) != serverFinal)
        throw new Error("Server's final response is unexpected");
      return '';
    });

    // Send the message signifying we've verified the server.
    yield verificationPromise;
  }
}
ScramModule.isClientFirst = true;

function makeSCRAMModule(hashName, hashLength) {
  class ConcreteScramModule extends ScramModule {
    constructor(server, hostname, options) {
      super(hashName, hashLength, options);
    }
  }

  return ConcreteScramModule;
}


return {
  "CRAM-MD5": CramMD5Module,
  "SCRAM-SHA-1": makeSCRAMModule("SHA-1", 20),
  "SCRAM-SHA-256": makeSCRAMModule("SHA-256", 32),
};
}));
