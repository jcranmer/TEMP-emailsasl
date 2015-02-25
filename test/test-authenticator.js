var assert = require("assert");
var sasl = require("../src/sasl");

if (typeof Promise === "undefined") {
  var ES6Promise = require("es6-promise");
  ES6Promise.polyfill();
}

if (typeof String.prototype.normalize === "undefined" ||
    '\u00aa'.normalize("NFKC") == '\u00aa') {
  var unorm = require('unorm');
  String.prototype.normalize = function (kind) {
    return unorm[kind.toLowerCase()](this);
  };
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

// Note: the test vectors for successful auth parameters are derived, wherever
// possible, from the official test vectors in their specifications.

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
    assert.throws(function () {
      new sasl.Authenticator("imap", "localhost.localdomain", [],
        { desiredAuthMethods: "not an array" });
    });
  });
  test('Authentication method fallback', function() {
    function makeAuth(methods, opts) {
      if (opts === undefined)
        opts = {user: 'a', pass: 'b', oauthbearer: 'somestring'};
      return new sasl.Authenticator("imap", "localhost.localdomain", methods,
        opts);
    }
    var auth = makeAuth(["LOGIN", "PLAIN"]);
    assert.equal(auth.tryNextAuth()[0], "PLAIN");
    assert.equal(auth.tryNextAuth()[0], "LOGIN");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["PLAIN", "SCRAM-SHA-1", "CRAM-MD5"]);
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth()[0], "CRAM-MD5");
    assert.equal(auth.tryNextAuth()[0], "PLAIN");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["SCRAM-SHA-256", "SCRAM-SHA-1"]);
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-256");
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["XOAUTH2", "SCRAM-SHA-1", "PLAIN"]);
    assert.equal(auth.tryNextAuth()[0], "XOAUTH2");
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth()[0], "PLAIN");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["XOAUTH2", "SCRAM-SHA-1", "PLAIN"],
      {user: "a", pass: "b"});
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth()[0], "PLAIN");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["XOAUTH2", "SCRAM-SHA-1", "PLAIN"],
      {user: "a", oauthbearer: "bearerstring"});
    assert.equal(auth.tryNextAuth()[0], "XOAUTH2");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["XOAUTH2", "SCRAM-SHA-1", "PLAIN"], {});
    assert.equal(auth.tryNextAuth(), null);

    // Why would you ever do this? ... Oh well.
    auth = makeAuth(["SCRAM-SHA-1", "PLAIN"],
      {user: "a", pass: "b", desiredAuthMethods: ["PLAIN", "SCRAM-SHA-1"]});
    assert.equal(auth.tryNextAuth()[0], "PLAIN");
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth(), null);

    auth = makeAuth(["SCRAM-SHA-1", "PLAIN"],
      {user: "a", pass: "b", desiredAuthMethods: ["EXTERNAL"]});
    assert.equal(auth.tryNextAuth(), null);

    // Check the expected parameter
    auth = makeAuth(["SCRAM-SHA-1", "PLAIN", "XOAUTH2", "CRAM-MD5"],
      {user: "a", pass: "b", oauthbearer: "bearerstring",
       desiredAuthMethods: "encrypted"});
    assert.equal(auth.tryNextAuth()[0], "SCRAM-SHA-1");
    assert.equal(auth.tryNextAuth()[0], "CRAM-MD5");
    assert.equal(auth.tryNextAuth(), null);

  });
});

suite('PLAIN', function () {
  test('Basic support', function () {
    var auth = quickAuth('PLAIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["PLAIN", true]);
    return auth.authStep("")
      .then(expectStr("AHRpbQB0YW5zdGFhZnRhbnN0YWFm"));
  });
  test('SASLprep username and password', function () {
    var auth = quickAuth('PLAIN',
      {user: "ti\u00adm", pass: "tanst\u00adaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["PLAIN", true]);
    return auth.authStep("")
      .then(expectStr("AHRpbQB0YW5zdGFhZnRhbnN0YWFm"));
  });
  test('Excessively chatty server', function () {
    var auth = quickAuth('PLAIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["PLAIN", true]);
    return auth.authStep("")
      .then(expectAndSend(auth, "AHRpbQB0YW5zdGFhZnRhbnN0YWFm", "AAAA"))
      .then(function (e) { throw new Error("Expected error"); },
            function (e) { assert.equal(e.message, "Too many steps"); });
  });
});

suite('LOGIN', function () {
  test('Basic support', function () {
    var auth = quickAuth('LOGIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["LOGIN", false]);
    return auth.authStep("VXNlciBOYW1lAA==")
      .then(expectAndSend(auth, "dGlt", "UGFzc3dvcmQA"))
      .then(expectStr("dGFuc3RhYWZ0YW5zdGFhZg=="));
  });
  test('SASLprep username and password', function () {
    var auth = quickAuth('LOGIN',
      {user: "tim\u00ad", pass: "\u00adtanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["LOGIN", false]);
    return auth.authStep("VXNlciBOYW1lAA==")
      .then(expectAndSend(auth, "dGlt", "UGFzc3dvcmQA"))
      .then(expectStr("dGFuc3RhYWZ0YW5zdGFhZg=="));
  });
  test('Excessively chatty server', function () {
    var auth = quickAuth('LOGIN', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["LOGIN", false]);
    return auth.authStep("VXNlciBOYW1lAA==")
      .then(expectAndSend(auth, "dGlt", "UGFzc3dvcmQA"))
      .then(expectAndSend(auth, "dGFuc3RhYWZ0YW5zdGFhZg==", ""))
      .then(function (e) { throw new Error("Expected error"); },
            function (e) { assert.equal(e.message, "Too many steps"); });
  });
});

suite('CRAM-MD5', function () {
  test('Basic support', function () {
    var auth = quickAuth('CRAM-MD5', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["CRAM-MD5", false]);
    return auth.authStep("PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+")
      .then(expectStr("dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw"));
  });
  test('SASLprep username and password', function () {
    var auth = quickAuth('CRAM-MD5',
      {user: "\u00adtim", pass: "tanstaaf\u00adtanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["CRAM-MD5", false]);
    return auth.authStep("PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+")
      .then(expectStr("dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw"));
  });
  test('Excessively chatty server', function () {
    var auth = quickAuth('CRAM-MD5', {user: "tim", pass: "tanstaaftanstaaf"});
    assert.deepEqual(auth.tryNextAuth(), ["CRAM-MD5", false]);
    return auth.authStep("PDE4OTYuNjk3MTcwOTUyQHBvc3RvZmZpY2UucmVzdG9uLm1jaS5uZXQ+")
      .then(expectAndSend(auth, "dGltIGI5MTNhNjAyYzdlZGE3YTQ5NWI0ZTZlNzMzNGQzODkw", ""))
      .then(function (e) { throw new Error("Expected error"); },
            function (e) { assert.equal(e.message, "Too many steps"); });
  });
});

suite('SCRAM-SHA-1', function () {
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
  test('SASLprep username and password', function () {
    var auth = quickAuth('SCRAM-SHA-1',
      {user: "user\u00ad", pass: "pencil\u00ad"});
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
  test('Random nonce', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    var nonce1 = auth._authModule.nonce;
    auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    var nonce2 = auth._authModule.nonce;
    // Two nonces should not be equal...
    assert.notEqual(nonce1, nonce2);
    // ... but be of the same length ...
    assert.equal(nonce1.length, nonce2.length);
    // ... this much exactly (base64-encoded length of internal hash size, or
    // 20 bytes).
    assert.equal(nonce1.length, Math.ceil(20 / 3) * 4);
  });
  test('Misauthenticated server', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    auth._authModule.nonce = 'fyko+d2lbbFgONRv9qkxdawL';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM",
        "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng=="))
      .then(expectAndSend(auth,
        "Yz1iaXdzLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdMM3JmY05IWUpZMVpWdldWczdqLHA9djBYOHYzQnoyVDBDSkdiSlF5RjBYK0hJNFRzPQ==",
        "dj1ybUY5cHFWOFM3c3VAAAAAAAAAAAAAAAAAAAAA"))
      .then(function (e) { assert.fail(false, true, "Server should fail"); },
        function (e) {
          assert.equal(e.message, "Server's final response is unexpected");
        });
  });
  test('Malformed server-first response (missing s=)', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    auth._authModule.nonce = 'fyko+d2lbbFgONRv9qkxdawL';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM",
        "cj1meWtvK2QybGIsaT00MDk2"))
      .then(function (e) { assert.fail(false, true, "Server should fail"); },
        function (e) { assert.equal(e.message, "Malformed server response"); });
  });
  test('Malformed server-first response (out-of-order)', function () {
    var auth = quickAuth('SCRAM-SHA-1', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-1", true]);
    auth._authModule.nonce = 'fyko+d2lbbFgONRv9qkxdawL';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ZnlrbytkMmxiYkZnT05Sdjlxa3hkYXdM",
        "cj1meWtvK2QybGIsaT00MDk2LHM9UVNYQ1IrUTZzZWs4YmY5Mg=="))
      .then(function (e) { assert.fail(false, true, "Server should fail"); },
        function (e) { assert.equal(e.message, "Malformed server response"); });
  });
});

suite('SCRAM-SHA-256', function () {
  test('Basic support', function () {
    var auth = quickAuth('SCRAM-SHA-256', {user: "user", pass: "pencil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-256", true]);
    auth._authModule.nonce = 'rOprNGfwEbeRWgbNEkqO';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=",
        "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY="))
      .then(expectAndSend(auth,
        "Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTUhnc3FtbWl6N0FuZFZRPQ==",
        "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ=="))
      .then(expectStr(""));
  });
  test('SASLprep username and password', function () {
    var auth = quickAuth('SCRAM-SHA-256',
      {user: "\u00aduser", pass: "pe\u00adncil"});
    assert.deepEqual(auth.tryNextAuth(), ["SCRAM-SHA-256", true]);
    auth._authModule.nonce = 'rOprNGfwEbeRWgbNEkqO';
    return auth.authStep("")
      .then(expectAndSend(auth,
        "biwsbj11c2VyLHI9ck9wck5HZndFYmVSV2diTkVrcU8=",
        "cj1yT3ByTkdmd0ViZVJXZ2JORWtxTyVodllEcFdVYTJSYVRDQWZ1eEZJbGopaE5sRiRrMCxzPVcyMlphSjBTTlk3c29Fc1VFamI2Z1E9PSxpPTQwOTY="))
      .then(expectAndSend(auth,
        "Yz1iaXdzLHI9ck9wck5HZndFYmVSV2diTkVrcU8laHZZRHBXVWEyUmFUQ0FmdXhGSWxqKWhObEYkazAscD1kSHpiWmFwV0lrNGpVaE4rVXRlOXl0YWc5empmTUhnc3FtbWl6N0FuZFZRPQ==",
        "dj02cnJpVFJCaTIzV3BSUi93dHVwK21NaFVaVW4vZEI1bkxUSlJzamw5NUc0PQ=="))
      .then(expectStr(""));
  });
});

suite('XOAUTH2', function () {
  test('Basic support', function () {
    var auth = quickAuth('XOAUTH2', {
      user: "someuser@example.com",
      oauthbearer: "vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg=="
    });
    assert.deepEqual(auth.tryNextAuth(), ["XOAUTH2", true]);
    return auth.authStep("")
      .then(expectStr("dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB2RjlkZnQ0cW1UYzJOdmIzUmxja0JoZEhSaGRtbHpkR0V1WTI5dENnPT0BAQ=="));
  });
  test('Server auth error', function () {
    var auth = quickAuth('XOAUTH2', {
      user: "someuser@example.com",
      oauthbearer: "vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg=="
    });
    assert.deepEqual(auth.tryNextAuth(), ["XOAUTH2", true]);
    return auth.authStep("")
      .then(expectAndSend(auth,
          "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB2RjlkZnQ0cW1UYzJOdmIzUmxja0JoZEhSaGRtbHpkR0V1WTI5dENnPT0BAQ==",
         "eyJzdGF0dXMiOiI0MDEiLCJzY2hlbWVzIjoiYmVhcmVyIG1hYyIsInNjb3BlIjoiaHR0cHM6Ly9tYWlsLmdvb2dsZS5jb20vIn0K"))
      .then(expectStr(""));
  });
});

suite('ANONYMOUS', function () {
  test('Basic support', function () {
    var auth = quickAuth('ANONYMOUS', {user: "sirhc",
      desiredAuthMethods: ['ANONYMOUS']});
    assert.deepEqual(auth.tryNextAuth(), ["ANONYMOUS", true]);
    return auth.authStep("")
      .then(expectStr("c2lyaGM="));
  });
  test('Only if requested', function () {
    var auth = quickAuth('ANONYMOUS', {user: "sirhc"});
    assert.equal(auth.tryNextAuth(), null);
  });
  test('No trace request', function () {
    var auth = quickAuth('ANONYMOUS', {desiredAuthMethods: ['ANONYMOUS']});
    assert.deepEqual(auth.tryNextAuth(), ["ANONYMOUS", true]);
    return auth.authStep("")
      .then(expectStr(""));
  });
});

