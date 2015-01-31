var assert = require("assert");
var sasl = require("../src/sasl");

function quickAuth(mechanism, opts) {
  return new sasl.Authenticator("imap", "localhost.localdomain",
    [mechanism], opts);
}

suite('sasl.Authenticator', function () {
  test('Parameter sanity', function () {
    assert.throws(function () {
      new sasl.Authenticator();
    });
    assert.throws(function () {
      new sasl.Authenticator("imap");
    });
    assert.throws(function () {
      new sasl.Authenticator("imap", "localhost");
    });
    assert.throws(function () {
      new sasl.Authenticator("imap", "localhost.localdomain");
    });
    assert.throws(function () {
      new sasl.Authenticator("imap", "localhost.localdomain", []);
    });
    assert.doesNotThrow(function () {
      new sasl.Authenticator("imap", "localhost.localdomain", ["PLAIN"]);
    });
  });
});

suite('PLAIN auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('PLAIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["PLAIN", true]);
    assert.equal(auth.authStep(""), "AHRpbQB0YW5zdGFhZnRhbnN0YWFm");
  });
});

suite('LOGIN auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('LOGIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["LOGIN", false]);
    assert.equal(auth.authStep("VXNlciBOYW1lAA=="), "dGlt");
    assert.equal(auth.authStep("UGFzc3dvcmQA"), "dGFuc3RhYWZ0YW5zdGFhZg==");
  });
});
