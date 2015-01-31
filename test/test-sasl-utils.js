var assert = require("assert");
var saslutils = require("../src/sasl-utils");

suite('sasl-utils', function () {
  test('saslPrep', function () {
    var testVectors = [
      // See RFC 4013, §3
      ['I\u00adX', 'IX'],
      ['user', 'user'],
      ['USER', 'USER'],
      //['\u00aa', 'a'],
      //['\u2618', 'IX'], eff'ing node
      // Some more tests for our mapping
      ['\u200b', ' '],
    ];
    testVectors.forEach(function (d) {
      assert.equal(saslutils.saslPrep(d[0]), d[1]);
    });
  });
});
