(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['./sasl-utils'], factory);
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory(require('./sasl-utils'), require('./sasl-crypto-polyfill'));
  } else {
    // Browser globals (root is window)
    root.saslCram = factory(root.saslUtils);
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
CramMD5Module.prototype.executeSteps = function*(initChallenge) {
  var hmacAlgorithm = {
    name: "HMAC",
    hash: "MD5",
    length: 128
  };
  var result = crypto.subtle.importKey("raw",
    new Buffer(saslUtils.saslPrep(this.pass), "utf-8"),
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
 * SCRAM SASL mechanism family-- see RFC 5802 for details.
 */
function makeSCRAMModule(hashName, hashLength) {
  var hmacAlgorithm = {
    name: "HMAC",
    hash: hashName,
    length: hashLength
  };
  function ScramModule(server, hostname, options) {
    this.user = options.user;
    this.pass = options.pass;
    this.nonce = saslUtils.arrayBufferToBase64(
      crypto.getRandomValues(new Uint8Array(hashLength)));
  }
  ScramModule.isClientFirst = true;
  ScramModule.prototype.executeSteps = function*() {
    var user = saslUtils.saslPrep(this.user)
                        .replace(',', "=2C")
                        .replace('=', "=3D");
    var gs2Header = 'n,,';
    var clientFirst = 'n=' + user + ',r=' + this.nonce;
    var response = yield saslUtils.stringToBase64UTF8(gs2Header + clientFirst);

    // Parse the server response
    var serverFirst = saslUtils.base64ToArrayBuffer(response).toString("utf-8");
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
      saslUtils.saslPrep(this.pass),
      pbkdfAlgorithm, false, ['deriveKey']).then(function (passwordKey) {
        return crypto.subtle.deriveKey(pbkdfAlgorithm, passwordKey,
          hmacAlgorithm, false, ['sign']);
    });

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    var clientKey = saltedPassword.then(function (saltedPassword) {
      return crypto.subtle.sign(hmacAlgorithm, saltedPassword,
        new Buffer("Client Key", "utf-8"));
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
        new Buffer(authMessage, 'utf-8'));
    });

    // ClientProof := ClientKey XOR ClientSignature
    var clientProof = Promise.all([clientKey, clientSignature]).then(
        function (values) {
      var clientKey = values[0];
      var clientSignature = values[1];
      var clientProof = new Uint8Array(clientSignature.length);
      for (var i = 0; i < clientProof.length; i++)
        clientProof[i] = clientKey[i] ^ clientSignature[i];
      return clientProof;
    });

    // Now we can output the final message
    var serverFinal = yield clientProof.then(function (clientProof) {
      return saslUtils.stringToBase64UTF8(clientFinal + ',p=' +
          saslUtils.arrayBufferToBase64(clientProof));
    });

    // Verify the server response
    // ServerKey := HMAC(SaltedPassword, "Server Key")
    var serverKey = saltedPassword.then(function (saltedPassword) {
      return crypto.subtle.sign(hmacAlgorithm, saltedPassword,
        new Buffer("Server Key", "utf-8"));
    }).then(function (serverKey) {
      return crypto.subtle.importKey("raw", serverKey, hmacAlgorithm, false,
          ['sign']);
    });

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    var serverSignature = serverKey.then(function (serverKey) {
      return crypto.subtle.sign(hmacAlgorithm, serverKey,
          new Buffer(authMessage, 'utf-8'));
    });

    var verificationPromise = serverSignature.then(function (serverSignature) {
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
  "SCRAM-SHA-384": makeSCRAMModule("SHA-384", 48),
  "SCRAM-SHA-512": makeSCRAMModule("SHA-512", 64),
};
}));
