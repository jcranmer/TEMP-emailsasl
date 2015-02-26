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
    jsdoc: {
      src: ['src/*.js'],
      options: {
        destination: 'docs',
        readme: 'README.md',
        private: false,
      },
    },
  });

  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-jsdoc');

  grunt.registerTask('test', ['mochaTest']);
  grunt.registerTask('docs', ['jsdoc']);
  grunt.registerTask('default', ['test']);
};
