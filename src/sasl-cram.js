/**
 * A library of challenge-response SASL mechanisms. These are split out from the
 * main module, as these require more advanced crypto support.
 * @module sasl-cram
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

var hexString = "0123456789abcdef";
var hexBytes = [];
for (var i = 0; i < 256; i++)
  hexBytes[i] = hexString[Math.trunc(i / 16)] + hexString[i % 16];

/**
 * CRAM-MD5 SASL mechanism -- see RFC 2195 for details.
 */
function CramMD5Module(server, hostname, options) {
  this.user = options.user;
  this.pass = options.pass;
}
CramMD5Module.isClientFirst = false;
CramMD5Module.prototype.isValid = function () {
  return this.user && this.pass;
};
CramMD5Module.prototype.executeSteps = function*(initChallenge) {
  var hmacAlgorithm = {
    name: "HMAC",
    hash: "MD5",
    length: 128
  };
  var result = crypto.subtle.importKey("raw",
    saslUtils.stringToArrayBuffer(saslUtils.saslPrep(this.pass)),
    hmacAlgorithm, false, ['sign']
  ).then(function (hmacKey) {
    return crypto.subtle.sign(hmacAlgorithm, hmacKey,
      saslUtils.base64ToArrayBuffer(initChallenge));
  }).then((function (result) {
    var hexStr = '';
    for (var i = 0; i < result.length; i++)
      hexStr += hexBytes[result[i]];
    return saslUtils.stringToBase64UTF8(
      saslUtils.saslPrep(this.user) + " " + hexStr);
  }).bind(this));

  yield result;
};

/**
 * SCRAM SASL mechanism family -- see RFC 5802 for details. This is actually a
 * family of possible mechanisms derivable from the IANA hash list
 * <http://www.iana.org/assignments/hash-function-text-names>, but registration
 * requires a separate RFC. Presently, SHA-1 is explicitly registered and
 * SHA-256 is a draft RFC.
 */
function makeSCRAMModule(hashName, hashLength) {
  var hmacAlgorithm = {
    name: "HMAC",
    hash: hashName,
    length: hashLength * 8,
  };
  function ScramModule(server, hostname, options) {
    this.user = options.user;
    this.pass = options.pass;
    this.nonce = saslUtils.arrayBufferToBase64(
      crypto.getRandomValues(new Uint8Array(hashLength)));
  }
  ScramModule.isClientFirst = true;
  ScramModule.prototype.isValid = function () {
    return this.user && this.pass;
  };
  ScramModule.prototype.executeSteps = function*() {
    var user = saslUtils.saslPrep(this.user)
                        .replace(',', "=2C")
                        .replace('=', "=3D");
    var gs2Header = 'n,,';
    var clientFirst = 'n=' + user + ',r=' + this.nonce;
    var response = yield saslUtils.stringToBase64UTF8(gs2Header + clientFirst);

    // Parse the server response
    var serverFirst = saslUtils.base64ToBinaryString(response);
    response = serverFirst.split(',');
    if (response[0].substring(0, 2) == 'm=')
      response.shift();
    if (response[0].substring(0, 2) != 'r=')
      throw new Error("Malformed server response");
    var servernonce = response[0].substring(2);
    if (response[1].substring(0, 2) != 's=')
      throw new Error("Malformed server response");
    var salt = saslUtils.base64ToArrayBuffer(response[1].substring(2));
    if (response[2].substring(0, 2) != 'i=')
      throw new Error("Malformed server response");
    var iterCount = parseInt(response[2].substring(2));

    var clientFinal = 'c=' + saslUtils.stringToBase64UTF8(gs2Header) + ',r=' +
      servernonce;
    var authMessage = [clientFirst, serverFirst, clientFinal].join(',');

    // Compute the ClientProof variable
    // SaltedPassword := Hi(Normalize(password), salt, i)
    var pbkdfAlgorithm = {
      name: "PBKDF2",
      hash: hashName,
      salt: salt,
      iterations: iterCount
    };
    var saltedPassword = crypto.subtle.importKey("raw",
      saslUtils.stringToArrayBuffer(saslUtils.saslPrep(this.pass)),
      pbkdfAlgorithm, false, ['deriveKey']).then(function (passwordKey) {
      hmacAlgorithm.length = 160;
        return crypto.subtle.deriveKey(pbkdfAlgorithm, passwordKey,
          hmacAlgorithm, false, ['sign']);
    });

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    var clientKey = saltedPassword.then(function (saltedPassword) {
      return crypto.subtle.sign(hmacAlgorithm, saltedPassword,
        saslUtils.stringToArrayBuffer("Client Key"));
    });

    // StoredKey := H(ClientKey)
    var storedKey = clientKey.then(function (clientKey) {
      return crypto.subtle.digest(hashName, clientKey);
    }).then(function (storedKey) {
      return crypto.subtle.importKey("raw", storedKey, hmacAlgorithm, false,
        ['sign']);
    });

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    var clientSignature = storedKey.then(function (storedKey) {
      return crypto.subtle.sign(hmacAlgorithm, storedKey,
        saslUtils.stringToArrayBuffer(authMessage));
    });

    // ClientProof := ClientKey XOR ClientSignature
    var clientProof = Promise.all([clientKey, clientSignature]).then(
        function (values) {
      var clientKey = new Uint8Array(values[0]);
      var clientSignature = new Uint8Array(values[1]);
      var clientProof = new Uint8Array(clientSignature.length);
      for (var i = 0; i < clientProof.length; i++)
        clientProof[i] = clientKey[i] ^ clientSignature[i];
      return clientProof;
    });

    // Now we can output the final message.
    var serverFinal = yield clientProof.then(function (clientProof) {
      return saslUtils.stringToBase64UTF8(clientFinal + ',p=' +
          saslUtils.arrayBufferToBase64(clientProof));
    });

    // Verify the server response.
    // ServerKey := HMAC(SaltedPassword, "Server Key")
    var serverKey = saltedPassword.then(function (saltedPassword) {
      return crypto.subtle.sign(hmacAlgorithm, saltedPassword,
        saslUtils.stringToArrayBuffer("Server Key"));
    }).then(function (serverKey) {
      return crypto.subtle.importKey("raw", serverKey, hmacAlgorithm, false,
          ['sign']);
    });

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    var serverSignature = serverKey.then(function (serverKey) {
      return crypto.subtle.sign(hmacAlgorithm, serverKey,
        saslUtils.stringToArrayBuffer(authMessage));
    });

    var verificationPromise = serverSignature.then(function (serverSignature) {
      serverSignature = new Uint8Array(serverSignature);
      var expected = 'v=' + saslUtils.arrayBufferToBase64(serverSignature);
      if (saslUtils.stringToBase64UTF8(expected) != serverFinal)
        throw new Error("Server's final response is unexpected");
      return '';
    });

    // Send the message signifying we've verified the server.
    yield verificationPromise;
  };

  return ScramModule;
}


return {
  "CRAM-MD5": CramMD5Module,
  "SCRAM-SHA-1": makeSCRAMModule("SHA-1", 20),
  "SCRAM-SHA-256": makeSCRAMModule("SHA-256", 32),
};
}));
