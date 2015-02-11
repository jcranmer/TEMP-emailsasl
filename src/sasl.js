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
 * A class to run the SASL authentication procedures. This class handles the
 * responsibility both of negotiating the SASL mechanism to use (via
 * [tryNextAuth]{@link module:sasl.Authenticator#tryNextAuth}) and of the actual
 * challenge/response nature of the framework (via [authStep]{@link
 * module:sasl.Authenticator#authStep}).
 *
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
 * @param {String[]|String} options.desiredAuthMethods
 *                             If present, this overrides the default
 *                             authentication method list for which methods are
 *                             preferred and acceptable. Methods are tried in
 *                             the order they are present in the array.
 *                             Alternatively, the value "encrypted" selects only
 *                             methods that do challenge-response password-based
 *                             authentication (e.g., CRAM-MD5, SCRAM-SHA-1).
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
  this.options = options || {};

  // Choose the methods to try in order. The list is reversed, since we pop off
  // in #tryNextAuth below.
  var authMethods = this.options.desiredAuthMethods || desiredAuthMethods;
  if (authMethods == "encrypted")
    authMethods = encryptedMethods;
  else if (!Array.isArray(authMethods))
    throw new Error("desiredAuthMethods must either be an array or encrypted");

  this._authMethods = authMethods.filter(function (m) {
    return supportedMechanisms.indexOf(m) >= 0;
  });
  this._authMethods.reverse();
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
  // Do we have another auth method left to try?
  while (this._authMethods.length != 0) {
    this._currentAuthMethod = this._authMethods.pop();
    var authClass = saslModules[this._currentAuthMethod];
    this._authModule = new (authClass)(this.service, this.hostname,
      this.options);
    if (!this._authModule.isValid())
      continue;

    return [this._currentAuthMethod, authClass.isClientFirst];
  }

  // Reset auth parameters
  this._authModule = null;
  this._authSteps = null;
  this._currentAuthMethod = '';

  return null;
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
AuthPlainModule.prototype.isValid = function () {
  return this.user && this.pass;
};
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
AuthLoginModule.prototype.isValid = function () {
  return this.user && this.pass;
};
AuthLoginModule.prototype.executeSteps = function*() {
  // Ignore what the server sends.
  yield saslUtils.stringToBase64UTF8(saslUtils.saslPrep(this.user));
  yield saslUtils.stringToBase64UTF8(saslUtils.saslPrep(this.pass));
};
addSaslModule("LOGIN", AuthLoginModule);

/**
 * ANONYMOUS SASL mechanism -- see RFC 4505 for details. We do not advertise
 * this mechanism in the default list of mechanisms; the user has to
 * specifically request it.
 */
function AuthAnonModule(server, hostname, options) {
  this.user = options.user || "";
}
AuthAnonModule.isClientFirst = true;
AuthAnonModule.prototype.isValid = function () {
  return true;
};
AuthAnonModule.prototype.executeSteps = function*() {
  // No SASLprep--the user is really an authzid here, and that's not SASLprep'd
  // (see §3 of RFC 4505 for more information).
  yield saslUtils.stringToBase64UTF8(this.user);
};
addSaslModule("ANONYMOUS", AuthAnonModule);

/**
 * XOAUTH2 SASL mechanism -- see
 * <https://developers.google.com/gmail/xoauth2_protocol> for details. This is
 * a fork of <https://tools.ietf.org/html/draft-ietf-kitten-sasl-oauth>.
 */
function AuthXOAuth2Module(server, hostname, options) {
  this.user = options.user;
  this.bearer = options.oauthbearer;
}
AuthXOAuth2Module.isClientFirst = true;
AuthXOAuth2Module.prototype.isValid = function () {
  return this.user && this.bearer;
};
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

// Import the encrypted methods from sasl-cram.js.
var encryptedMethods = [];
for (var method in saslCram) {
  addSaslModule(method, saslCram[method]);
  encryptedMethods.push(method);
}
// The saslCram list comes in increasing order of security.
encryptedMethods.reverse();

// Build the desired authentication mechanism list. We prefer SSO mechanisms
// first (since they'll be disabled if there's insufficient information), then
// encrypted passwords, then unencrypted mechanisms.
var desiredAuthMethods = ["XOAUTH2"].concat(encryptedMethods).concat([
  "PLAIN", "LOGIN"
]);


return {
  Authenticator: Authenticator,
  addSaslModule: addSaslModule,
  desiredAuthMethods: desiredAuthMethods
};
}));
