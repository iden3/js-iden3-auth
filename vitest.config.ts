import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    testTimeout: 60000,
    include: ['**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}']
  },
  resolve: {
    alias: {
      '@lib/circuits': resolve(__dirname, './src/circuits'),
      '@lib/proofs': resolve(__dirname, './src/proofs'),
      '@lib/auth': resolve(__dirname, './src/auth'),
      '@lib/state': resolve(__dirname, './src/state'),
      '@lib/cache': resolve(__dirname, './src/cache'),
      '@lib/constants': resolve(__dirname, './src/constants')
    }
  }
});
