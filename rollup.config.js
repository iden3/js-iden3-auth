import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonJS from '@rollup/plugin-commonjs';
import virtual from '@rollup/plugin-virtual';
import replace from '@rollup/plugin-replace';
import typescript from '@rollup/plugin-typescript';
import sourcemaps from 'rollup-plugin-sourcemaps';

const empty = 'export default {}';

export default [
    {
        input: 'src/index.ts',
        output: {
            dir: 'dist/cjs',
            sourcemap: 'inline',
            format: 'cjs',
        },
        plugins: [
            typescript({
                tsconfig: './tsconfig-cjs.json'
            }),
            commonJS(),
            nodeResolve(),
            sourcemaps(),
        ]
    },
    /* // use for browser later.
    {
        input: 'src/index.ts',
        output: {
            dir: 'dist/mjs',
            sourcemap: 'inline',
            globals: {
                os: 'null'
            },
            name: 'iden3auth',
            format: 'iife',
        },
        plugins: [
            virtual({
                fs: empty,
                readline: empty,
                ejs: empty,
            }),
            nodeResolve({
                browser: true,
                preferBuiltins: false,
                exportConditions: ['browser', 'default', 'module', 'require']
            }),
            commonJS(),
            replace({
                preventAssignment: false,
                'process.browser': true
            }),
            typescript({
                tsconfig: './tsconfig.json'
            })
        ]
    }
    */

]
