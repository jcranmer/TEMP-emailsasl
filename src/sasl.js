/**
 * The main SASL module.
 * @module sasl
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    // AMD. Register as an anonymous module.
    define(['./sasl-utils', './sasl-cram'], factory);
  } else if (typeof exports === 'object') {
    // Node. Does not work with strict CommonJS, but
    // only CommonJS-like environments that support module.exports,
    // like Node.
    module.exports = factory(require('./sasl-utils'), require('./sasl-cram'));
  } else {
    // Browser globals (root is window)
    root.sasl = factory(root.saslUtils, root.saslCram);
  }
}(this, function (saslUtils, saslCram) {

/**
 * The service name is the SASL service name parameter (typically the lowercase
 * name of the protocol, e.g., imap or smtp).
 * @constructor
 * @alias module:sasl.Authenticator
 * @param {String} serviceName The SASL service name parameter (e.g., imap).
 * @param {String} hostname    The hostname to use as the realm for SASL.
 * @param {String[]} supportedMechanisms The list of mechanisms supported by the
 *                                       server.
 * @param {Object} options     An options dictionary. See the particular
 *                             mechanism for documentation about which
 *                             parameters are needed and which are optional.
 * @param {String} options.user The username to use for authentication.
 * @param {String} options.pass The password to use for authentication.
 */
function Authenticator(serviceName, hostname, supportedMechanisms, options) {
  if (!serviceName)
    throw new Exception("Service name is a required parameter");
  
  if (!hostname)
    throw new Exception("Host name is a required parameter");

  if (hostname.indexOf(".") < 0)
    throw new Exception("Host name must be a fully-qualified domain name");

  if (!Array.isArray(supportedMechanisms) || supportedMechanisms.length == 0)
    throw new Exception("Need a list of mechanisms the server supports");

  this.service = serviceName;
  this.hostname = hostname;
  this.options = options;

  // XXX: Need prioritized list of auth methods
  var desiredAuthMethods = Object.keys(saslModules);
  this._authMethods = desiredAuthMethods.filter(function (m) {
    return supportedMechanisms.indexOf(m) >= 0;
  });
}

/**
 * Try the next available SASL authentication mechanism. If no more mechanisms
 * are available, null is returned. Otherwise, an array of two elements is
 * returned, the first being the name of the mechanism to use, and the second
 * whether or not the mechanism is client-first (and could therefore leverage a
 * SASL-IR feature).
 *
 * @returns {?Array} If not null, the array has two elements as described above.
 */
Authenticator.prototype.tryNextAuth = function () {
  // Reset auth parameters
  this._authModule = null;
  this._authSteps = null;
  this._currentAuthMethod = '';
  this._currentAuthClass = null;

  // Do we have another auth method left to try?
  if (this._authMethods.length == 0) {
    return null;
  }

  this._currentAuthMethod = this._authMethods.pop();
  this._currentAuthClass = saslModules[this._currentAuthMethod];
  this._authModule = new (this._currentAuthClass)(
    this.service, this.hostname, this.options);
  return [this._currentAuthMethod, this._currentAuthClass.isClientFirst];
};

/**
 * Perform a single authentication step. For a client initial-response, pass in
 * the empty string as the server's first challenge. All values are expected to
 * be base64-encoded strings, which means no translation is necessary when using
 * IMAP, SMTP, or similar protocols (except for stripping CRLF or protocol
 * tags).
 * @param {String} serverStep The base64-encoded server challenge.
 * @returns {Promise<String>} The base64-encoded client response.
 */
Authenticator.prototype.authStep = function (serverStep) {
  if (this._currentAuthMethod && !this._authSteps) {
    this._authSteps = this._authModule.executeSteps(serverStep);
    var result = this._authSteps.next();
  } else {
    var result = this._authSteps.next(serverStep);
  }
  return Promise.resolve(result.value);
};

var saslModules = {};

/**
 * Add a custom SASL mechanism, in addition to the ones already registered.
 *
 * SASL mechanisms should be registered with [IANA]{@link
 * http://www.iana.org/assignments/sasl-mechanisms}.
 *
 * @param {String} mechanism  The SASL mechanism string, in its canonical form.
 * @param {SaslModule} module The SASL module implementation.
 * @alias module:sasl.addSaslModule
 */
function addSaslModule(mechanism, module) {
  saslModules[mechanism] = module;
}

/**
 * PLAIN SASL mechanism -- see RFC 4616 for details.
 */
function AuthPlainModule(server, hostname, options) {
  this.user = options.user;
  this.pass = options.pass;
}
AuthPlainModule.isClientFirst = true;
AuthPlainModule.prototype.executeSteps = function*() {
  var message = "\0" + saslUtils.saslPrep(this.user) + "\0" +
    saslUtils.saslPrep(this.pass);
  yield saslUtils.stringToBase64UTF8(message);
};
addSaslModule("PLAIN", AuthPlainModule);

/**
 * LOGIN SASL mechanism -- see
 * <https://tools.ietf.org/html/draft-murchison-sasl-login-00> for details.
 */
function AuthLoginModule(server, hostname, options) {
  this.user = options.user;
  this.pass = options.pass;
}
AuthLoginModule.isClientFirst = false;
AuthLoginModule.prototype.executeSteps = function*() {
  // Ignore what the server sends.
  yield saslUtils.stringToBase64UTF8(saslUtils.saslPrep(this.user));
  yield saslUtils.stringToBase64UTF8(saslUtils.saslPrep(this.pass));
};
addSaslModule("LOGIN", AuthLoginModule);

/**
 * XOAUTH2 SASL mechanism -- see
 * <https://developers.google.com/gmail/xoauth2_protocol> for details. This is
 * a fork of <https://tools.ietf.org/html/draft-ietf-kitten-sasl-oauth>.
 */
function AuthXOAuth2Module(server, hostname, options) {
  this.bearer = options.oauthbearer;
}
AuthXOAuth2Module.isClientFirst = true;
AuthXOAuth2Module.prototype.executeSteps = function*() {
  var error = yield saslUtils.stringToBase64UTF8(
    "user=" + saslUtils.saslPrep(this.user) + "\x01auth=Bearer " +
    this.bearer + "\x01\x01");

  // If we succeeded, the server sends a success message instead of a
  // continuation, so we're only here if an error occurred. We still need to
  // send an empty response, though.
  yield "";
};
addSaslModule("XOAUTH2", AuthXOAuth2Module);




for (var method in saslCram) {
  addSaslModule(method, saslCram[method]);
}

return {
  Authenticator: Authenticator,
  addSaslModule: addSaslModule
};
}));
