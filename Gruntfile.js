module.exports = function(grunt) {
  'use strict';
  grunt.initConfig({
    mochaTest: {
      options: {
        reporter: 'spec',
        ui: 'tdd',
      },
      src: ['test/*.js'],
    },
  });

  grunt.loadNpmTasks('grunt-mocha-test');

  grunt.registerTask('test', ['mochaTest']);
  grunt.registerTask('default', ['test']);
};
