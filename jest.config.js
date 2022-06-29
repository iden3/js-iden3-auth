module.exports = {
    testTimeout: 20000,
    transform: {
        "^.+\\.tsx?$": "ts-jest",
    },
    testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$",
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
    moduleNameMapper: {
        "@lib/core/(.*)": "<rootDir>/src/core/$1",
        "@lib/protocol/(.*)": "<rootDir>/src/protocol/$1",
        "@lib/circuits/(.*)": "<rootDir>/src/circuits/$1",
        "@lib/proofs/(.*)": "<rootDir>/src/proofs/$1",
        "@lib/auth/(.*)": "<rootDir>/src/auth/$1",
        "@lib/state/(.*)": "<rootDir>/src/state/$1",
        "@lib/loaders/(.*)": "<rootDir>/src/loaders/$1"
    },
    // globals: {
    //     'jest-config': {
    //         tsConfig: 'tsconfig.test.json'
    //     }
    // }
};
