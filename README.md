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
features of some SASL mechanisms.

## Usage

### AMD

Require [sasl.js](src/sasl.js) as `sasl`.

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

## Custom SASL mechanisms
Custom SASL mechanisms can be registerd using `sasl.addSaslModule(mech, mod)`,
where

* **mech** is the SASL mechanism name, and
* **mod** is a SASL module class.

SASL module classes have the following API:
```javascript
function CustomModule(serviceName, hostname, options) { }
CustomModule.isClientFirst = /* */;
CustomModule.prototype.executeSteps = function*() {};
```

The parameters of the function are passed through from the `Authenticator`
constructor. The `isClientFirst` static property is a boolean property that, if
true, allows for an initial response to be sent without waiting for the server.
The `executeSteps` method is a generator.

# Supported SASL mechanisms

The following SASL mechanisms are supported:
### [PLAIN](http://tools.ietf.org/html/rfc4616)
* **options.user** Username
* **options.pass** Password
