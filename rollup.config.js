import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import terser from '@rollup/plugin-terser'

export default [
  {
    input: './src/index.js',
    output: [
      {
        file: './dist/boho.iife.js',
        format: 'iife',
        name: 'Boho',
        sourcemap: true
      },
      {
        file: './dist/boho.js',
        format: 'es',
        sourcemap: true
      }
    ],
    plugins: [
      resolve({
        preferBuiltins: false
      }),
      commonjs()
      , terser()
    ]
  },
  {
    input: './src/index.js',
    output: [
      {
        file: './dist/boho.cjs',
        format: 'cjs',
        exports: 'default'
      }
    ],
    plugins: [
      resolve({
        preferBuiltins: true
      }),
      commonjs()
      , terser()
    ]
  }

]
