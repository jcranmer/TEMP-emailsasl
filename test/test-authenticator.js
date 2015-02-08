var assert = require("assert");
var sasl = require("../src/sasl");

if (typeof Promise === "undefined") {
  var ES6Promise = require("es6-promise");
  ES6Promise.polyfill();
}

function quickAuth(mechanism, opts) {
  return new sasl.Authenticator("imap", "localhost.localdomain",
    [mechanism], opts);
}

function expectStr(expected) {
  return function (str) { assert.equal(str, expected); };
}

function expectAndSend(auth, expected, send) {
  return function (str) {
    assert.equal(str, expected);
    return auth.authStep(send);
  };
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
    return auth.authStep("")
      .then(expectStr("AHRpbQB0YW5zdGFhZnRhbnN0YWFm"));
  });
});

suite('LOGIN auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('LOGIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["LOGIN", false]);
    return auth.authStep("VXNlciBOYW1lAA==")
      .then(expectAndSend(auth, "dGlt", "UGFzc3dvcmQA"))
      .then(expectStr("dGFuc3RhYWZ0YW5zdGFhZg=="));
  });
});

suite('CRAM-MD5 auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('CRAM-MD5', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["CRAM-MD5", false]);
    return auth.authStep("PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+")
      .then(expectStr("dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw"));
  });
});

suite('SCRAM-SHA-1 auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    auth._authModule.nonce = 'fyko+d2lbbFgONRv9qkxdawL';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM",
        "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng=="))
      .then(expectAndSend(auth,
        "Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMM3JmY05IWUpZMVpWdldWczdqLHA9djBYOHYzQnoyVDBDSkdiSlF5RjBYK0hJNFRzPQ==",
        "dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9"))
      .then(expectStr(""));
  });
});
