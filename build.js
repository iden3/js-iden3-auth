const esbuild = require('esbuild');

console.log('START building bundle...');
esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  target: 'es2020',
  outfile: 'dist/cjs/index.js',
  sourcemap: false,
  format: 'cjs',
  legalComments: 'none',
  treeShaking: true,
});
console.log('FINISH building bundle');
