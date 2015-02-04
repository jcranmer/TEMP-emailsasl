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
Authenticator.prototype.authStep = function (serverStep) {
  if (this._currentAuthMethod && !this._authSteps) {
    this._authSteps = this._authModule.executeSteps(serverStep);
    return this._authSteps.next().value;
  }
  var result = this._authSteps.next(serverStep);
  return result.value;
};

var saslModules = {};
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

for (var method in saslCram) {
  addSaslModule(method, saslCram[method]);
}

return {
  Authenticator: Authenticator,
  addSaslModule: addSaslModule
};
}));
