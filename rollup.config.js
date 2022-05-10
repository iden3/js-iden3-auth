import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonJS from "@rollup/plugin-commonjs";
import virtual from "@rollup/plugin-virtual";
import replace from "@rollup/plugin-replace";
import typescript from "@rollup/plugin-typescript";
import execute from 'rollup-plugin-execute'

const empty = "export default {}";

export default [
    {
        input: "src/index.ts",
        output: {
            dir: "dist/cjs",
            sourcemap: "inline",
            format: "cjs",
        },
        plugins: [
            nodeResolve(),
            typescript({
                tsconfig: './tsconfig-cjs.json'
            }),
            execute(`
            cat >dist/cjs/package.json <<!EOF
{
    "type": "commonjs"
}
!EOF
            `)
        ]
    },

    {
        input: "src/index.ts",
        output: {
            dir: "dist/mjs",
            sourcemap: "inline",
            globals: {
                os: "null"
            },
            name: "iden3auth",
            format: "iife",
        },
        plugins: [
            virtual({
                fs: empty,
                os: empty,
                crypto: empty,
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
                // The current default is false, but they are changing it next version
                preventAssignment: false,
                "process.browser": true
            }),
            typescript({
                tsconfig: './tsconfig.json'
            })
        ]
    }]
