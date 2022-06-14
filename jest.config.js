module.exports = {
    testTimeout: 20000,
    transform: {
        "^.+\\.tsx?$": "ts-jest",
    },
    testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$",
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
    moduleNameMapper: {
        "@core/(.*)": "<rootDir>/src/core/$1",
        "@protocol/(.*)": "<rootDir>/src/protocol/$1",
        "@circuits/(.*)": "<rootDir>src/circuits/$1",
        "@proofs/(.*)": "<rootDir>src/proofs/$1",
        "@auth/(.*)": "<rootDir>src/auth/$1",
        "@state/(.*)": "<rootDir>src/state/$1",
        "@loaders/(.*)": "<rootDir>src/loaders/$1"
    }
};
