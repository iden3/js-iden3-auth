module.exports = {
  testTimeout: 60000,
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  },
  testRegex: '(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
  moduleNameMapper: {
    '@lib/circuits/(.*)': '<rootDir>/src/circuits/$1',
    '@lib/proofs/(.*)': '<rootDir>/src/proofs/$1',
    '@lib/auth/(.*)': '<rootDir>/src/auth/$1',
    '@lib/state/(.*)': '<rootDir>/src/state/$1',
    '@digitalbazaar/http-client': '<rootDir>/__mocks__/@digitalbazaar/http-client/dist/cjs/index.js'
  }
};
