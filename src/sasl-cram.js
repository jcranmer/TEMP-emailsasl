(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['./sasl-utils'], factory);
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory(require('./sasl-utils'), require('crypto'));
  } else {
    // Browser globals (root is window)
    root.saslCram = factory(root.saslUtils);
  }
}(this, function (saslUtils, crypto) {

/**
 * CRAM-MD5 SASL mechanism -- see RFC 2195 for details.
 */
function CramMD5Module(server, hostname, options) {
  this.user = options.user;
  this.pass = options.pass;
}
CramMD5Module.isClientFirst = false;
CramMD5Module.prototype.executeSteps = function*(initChallenge) {
  var hmac = crypto.createHmac("md5", saslUtils.saslPrep(this.pass));
  hmac.update(saslUtils.base64ToArrayBuffer(initChallenge));
  var result = hmac.digest("hex");
  yield saslUtils.stringToBase64UTF8(saslUtils.saslPrep(this.user) + " " +
    result);
};

/**
 * SCRAM SASL mechanism family-- see RFC 5802 for details.
 */
function makeSCRAMModule(hashName) {
  var hashLength = crypto.createHash(hashName).digest().length;
  function ScramModule(server, hostname, options) {
    this.user = options.user;
    this.pass = options.pass;
    this.nonce = crypto.randomBytes(hashLength).toString("base64");
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
    var saltedPassword = crypto.pbkdf2Sync(saslUtils.saslPrep(this.pass),
      salt, iterCount, hashLength);

    // ClientKey := HMAC(SaltedPassword, "Client Key")
    var hmac = crypto.createHmac(hashName, saltedPassword);
    hmac.update(new Buffer("Client Key", "utf-8"));
    var clientKey = hmac.digest();

    // StoredKey := H(ClientKey)
    var hash = crypto.createHash(hashName);
    hash.update(clientKey);
    var storedKey = hash.digest();

    // ClientSignature := HMAC(StoredKey, AuthMessage)
    hmac = crypto.createHmac(hashName, storedKey);
    hmac.update(authMessage, 'utf-8');
    var clientSignature = hmac.digest();

    // ClientProof := ClientKey XOR ClientSignature
    var clientProof = new Uint8Array(clientSignature.length);
    for (var i = 0; i < clientProof.length; i++)
      clientProof[i] = clientKey[i] ^ clientSignature[i];

    // Now we can output the final message
    var serverFinal = yield saslUtils.stringToBase64UTF8(
      clientFinal + ',p=' + new Buffer(clientProof).toString('base64'));

    // Verify the server response
    // ServerKey := HMAC(SaltedPassword, "Server Key")
    hmac = crypto.createHmac(hashName, saltedPassword);
    hmac.update(new Buffer("Server Key", "utf-8"));
    var serverKey = hmac.digest();

    // ServerSignature := HMAC(ServerKey, AuthMessage)
    hmac = crypto.createHmac(hashName, serverKey);
    hmac.update(authMessage, 'utf-8');
    var serverSignature = hmac.digest();
    var expected = 'v=' + serverSignature.toString('base64');
    if (saslUtils.stringToBase64UTF8(expected) != serverFinal)
      throw new Error("Server's final response is unexpected");

    // Send the message signifying we've verified the server.
    yield '';
  };

  return ScramModule;
}


return {
  "CRAM-MD5": CramMD5Module,
  "SCRAM-SHA-1": makeSCRAMModule("sha1"),
};
}));
