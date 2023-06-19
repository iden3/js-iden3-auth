const esbuild = require('esbuild');
const path = require('path');

console.log('START building bundle...');
esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'es2020',
  outfile: 'dist/cjs_bundle/index.js',
  sourcemap: false,
  format: 'cjs',
  legalComments: 'none',
  treeShaking: true,
});
console.log('FINISH building bundle');
