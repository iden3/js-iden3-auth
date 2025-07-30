module.exports = {
  testTimeout: 60000,
  transform: {
    '^.+\\.(t|j)sx?$': ['ts-jest', { useESM: true }]
  },
  transformIgnorePatterns: ['/node_modules/(?!((quick-lru)/))'],
  testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  moduleNameMapper: {
    '@lib/circuits/(.*)': '<rootDir>/src/circuits/$1',
    '@lib/proofs/(.*)': '<rootDir>/src/proofs/$1',
    '@lib/auth/(.*)': '<rootDir>/src/auth/$1',
    '@lib/state/(.*)': '<rootDir>/src/state/$1',
    '@lib/cache': '<rootDir>/src/cache',
    '@lib/constants': '<rootDir>/src/constants',
    '@digitalbazaar/http-client': '<rootDir>/__mocks__/@digitalbazaar/http-client/dist/cjs/index.js'
  },
  extensionsToTreatAsEsm: ['.ts']
};
