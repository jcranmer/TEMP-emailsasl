# Email SASL client library

The email SASL client library is a library that implements SASL authentication
and negotiation for clients, optimized for IMAP, SMTP, and similar protocols.

## What is SASL?

[SASL](http://tools.ietf.org/html/rfc4422) is a generic framework for hooking
custom authentication and authorization mechanisms into client protocols. These
mechanisms range from simple username/password pairs to complex authorization
schemes such as Kerberos.

In addition to providing client implementations of several of the SASL
mechanisms, this library provides an automatic fallback method of supported
authentication mechanisms. This library does not aim to implement these
mechanisms for the server side, nor does it attempt to support channel-binding
or ongoing encryption features of some SASL mechanisms.

Since the major email protocols all implement SASL by requiring that the text be
base64-encoded when sent over the protocol, this library automatically encodes
the client messages and decodes the server messages internally.

## Usage

This API requires the use of ES6 promises and generators, as well as the
TextEncoder and WebCrypto APIs. The latter are polyfilled for node.js use.

### AMD

Require [sasl.js](src/sasl.js) as `sasl`.

### Node.js

Require [sasl.js](src/sasl.js).

## API

The primary class is `sasl.Authenticator`, which implements the main layer used
by client protocol implementations. It can be created as such:

```javascript
var auth = new sasl.Authenticator(service, hostname, mechanisms, options);
```

where

* **service** is the service name registered in SASL. This is usually the
  protocol's name in lowercase, see [IANA's registration list](http://www.iana.org/assignments/gssapi-service-names/gssapi-service-names.xhtml)
  for more details.
* **hostname** is the fully-qualified domain name of the server host.
* **mechanisms** is an array of SASL mechanisms that the server supports.
* **options** is an optional argument containing authentication parameters for
  specific mechanisms, see below for more details.

The **user** and **pass** options on the **options** object are used by most
SASL mechanisms to initialize the username and password, respectively. In
addition to these two common options, the following options are supported by
the `Authenticator` class directly:
* **options.desiredAuthMethods** *Array* This list allows the client to override
  the desired authentication method order on a per-connection basis, trying the
  first method in the array, then the second, etc. Alternatively, using the
  string `encrypted` instead of an array selects only the authentication methods
  that encrypt the password before sending them (e.g., SCRAM-SHA-1 or CRAM-MD5,
  but not XOAUTH2 or PLAIN).

Using the authenticator object to actually run, for example, an IMAP connection
would look as follows:

```javascript
// imapCapabilities is returned by CAPABILITY
var methods = imapCapabilities.filter(x => x.startswith('AUTH='))
                              .map(x => x.substring(5));
var auth = new sasl.Authenticator("imap", host, methods, options);
var method;
while ((method = auth.tryNextAuth()) != null) {
  var line = getImapTag() + " AUTHENTICATE " + method[0];
  if (imapCapabilities.includes("SASL-IR") && method[1])
    line += " " + yield auth.authStep(""); // Send initial response
  server.sendLine(line);
  while (true) {
    line = server.parseResponse();
    if (line.isContinuation)
      server.sendLine(yield auth.authStep(line.continuationData));
    else
      break;
  }
  // The auth method succeeded!
  if (line.success)
    break;
  // If the auth method failed, try the next one...
}
```

The authenticator object has two methods. The `tryNextAuth` method is used to
select the next authentication method, and either returns `null` (if no more
authentication methods are available) or returns the array `[method,
clientFirst]`, indicating the name of the chosen method and whether a SASL
initial response is usable.

To actually perform an authentication method, the `authStep` method used. Its
parameter is a base64-encoded string value containing the server challenge (or
the empty string in case of SASL initial response), and it returns a Promise
which resolves to the base64-encoded string to send back to the server. The
Promise can also be rejected if the server challenges are malformed; in this
case, the authentication can be aborted (usually indicated by sending `*`
instead of `+`) before attempting the next mechanism.

## Custom SASL mechanisms
Custom SASL mechanisms can be registered using `sasl.addSaslModule(mech, mod)`,
where

* **mech** is the SASL mechanism name, and
* **mod** is a SASL module class.

SASL module classes have the following API:
```javascript
function CustomModule(serviceName, hostname, options) { }
CustomModule.isClientFirst = /* */;
CustomModule.prototype.isValid = function () {};
CustomModule.prototype.executeSteps = function*(initialChallenge) {};
```

The parameters of the function are passed through from the `Authenticator`
constructor. The `isClientFirst` static property is a boolean property that, if
true, allows for an initial response to be sent without waiting for the server.

The `isValid` method is a function that returns true if the configuration
details passed in via the options is sufficient to attempt the authentication
method. For example, the `XOAUTH2` mechanism would return false if a bearer
string were not present.

The `executeSteps` method is a generator. This generator produces a client
response for every server message sent to it. All messages are passed to and
from the SASL module as strings containing the base64-encoded message; the
`sasl-utils` module provides some utilities for handling these. The generator
can optionally return a Promise if the computations involved are asynchronous
(for example, using the WebCrypto API).

# Supported SASL mechanisms

The following SASL mechanisms are supported, along with the authentication
parameters they use:

### [ANONYMOUS](http://tools.ietf.org/html/rfc4505)
* **options.user** Username (optional)

Unlike other auth mechanisms, *ANONYMOUS* is only enabled if specifically
requested via `options.desiredAuthMethods`; this is to avoid being selected if
all other auth mechanisms fail.

### [CRAM-MD5](http://tools.ietf.org/html/rfc2195)
* **options.user** Username
* **options.pass** Password

### [LOGIN](https://tools.ietf.org/html/draft-murchison-sasl-login-00)
* **options.user** Username
* **options.pass** Password

### [PLAIN](http://tools.ietf.org/html/rfc4616)
* **options.user** Username
* **options.pass** Password

### [SCRAM-SHA-1](http://tools.ietf.org/html/rfc5802)
* **options.user** Username
* **options.pass** Password

### [SCRAM-SHA-256](http://tools.ietf.org/html/draft-hansen-scram-sha256)
* **options.user** Username
* **options.pass** Password

### XOAUTH2
* **options.user** Username
* **options.oauthbearer** *String* The OAuth2 Bearer token to authenticate with.

