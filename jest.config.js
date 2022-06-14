module.exports = {
    testTimeout: 20000,
    transform: {
        "^.+\\.tsx?$": "ts-jest",
    },
    testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.(jsx?|tsx?)$",
    moduleFileExtensions: ["ts", "tsx", "js", "jsx", "json", "node"],
    moduleNameMapper: {
        "@app/core/(.*)": "<rootDir>/src/core/$1",
        "@app/protocol/(.*)": "<rootDir>/src/protocol/$1",
        "@app/circuits/(.*)": "<rootDir>src/circuits/$1",
        "@app/proofs/(.*)": "<rootDir>src/proofs/$1",
        "@app/auth/(.*)": "<rootDir>src/auth/$1",
        "@app/state/(.*)": "<rootDir>src/state/$1",
        "@app/loaders/(.*)": "<rootDir>src/loaders/$1"
    }
};
