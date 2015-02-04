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

suite('CRAM-MD5 auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('CRAM-MD5', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["CRAM-MD5", false]);
    assert.equal(auth.authStep(
      "PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+"),
      "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw");
  });
});

suite('SCRAM-SHA-1 auth', function () {
  test('Basic support', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    auth._authModule.nonce = 'fyko+d2lbbFgONRv9qkxdawL';
    assert.equal(auth.authStep(""),
      "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM");
    assert.equal(auth.authStep("cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng=="),
      "Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMM3JmY05IWUpZMVpWdldWczdqLHA9djBYOHYzQnoyVDBDSkdiSlF5RjBYK0hJNFRzPQ==");
    assert.equal(auth.authStep("dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9"),
      "");
  });
});
