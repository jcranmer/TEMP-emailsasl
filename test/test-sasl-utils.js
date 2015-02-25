var assert = require("assert");
var saslutils = require("sasl-utils");

if (typeof String.prototype.normalize === "undefined" ||
    '\u00aa'.normalize("NFKC") == '\u00aa') {
  var unorm = require('unorm');
  String.prototype.normalize = function (kind) {
    return unorm[kind.toLowerCase()](this);
  };
}

suite('sasl-utils', function () {
  test('saslPrep', function () {
    var testVectors = [
      // See RFC 4013, §3
      ['I\u00adX', 'IX'],
      ['user', 'user'],
      ['USER', 'USER'],
      ['\u00aa', 'a'],
      ['\u2168', 'IX'],
      // Some more tests for our mapping
      ['\u200b', ' '],
    ];
    testVectors.forEach(function (d) {
      assert.equal(saslutils.saslPrep(d[0]), d[1]);
    });
  });
});
