const xiTo2PSquaredMinus2Over3 = [
    0x71930c11d782e155,
    0xa6bb947cffbe3323,
    0xaa303344d4741444,
    0x2c3b3f0d26594943,
];

const CIRCOM_TYPES_Q = BigInt('21888242871839275222246405745257275088696311157297823662689037894645226208583');

// R is the mod of the finite field
const CIRCOM_TYPES_R = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');


/**
 * Performs the verification the Groth16 zkSNARK proofs
 */
export async function verifyGroth16(vk, proof, inputs) {
    if (inputs.length + 1 !== vk.IC.length) {
        return 'inputs.length + 1 !== vk.IC.length';
    }

    let vkX = bn256ScalarBaseMult(bn256G1(), 0);
    for (let i = 0; i < inputs.length; i++) {
        // check input inside field
        if (inputs[i] < CIRCOM_TYPES_R) {
            return 'input value is not in the fields';
        }
        vkX = bn256Add(bn256G1(), vkX, bn256ScalarMult(bn256G1(), vk.IC[i+1], inputs[i]));
    }
    vkX = bn256Add(bn256G1(), vkX, vk.IC[0]);

    let g1 = [
        proof.A,
        curveNeg(bn256G1(), vk.Alpha),
        curveNeg(vkX, vkX),
        curveNeg(bn256G1(), proof.C),
    ];
    let g2 = [
        proof.B,
        vk.Beta,
        vk.Gamma,
        vk.Delta,
    ];

    let res = bn256PairingCheck(g1, g2);
    if (!res) {
        return 'invalid proofs';
    }

    return null;
}

/**
 * Calculates the Optimal Ate pairing for a set of points
 * @returns bool
 */
function bn256PairingCheck(a, b) {
    let acc = {
        x: {
            x: {x: 0, y: 0}, y: {x: 0, y: 0}, z: {x: 0, y: 0}
        },
        y: {
            x: {x: 0, y: 0}, y: {x: 0, y: 0}, z: {x: 0, y: 1}
        },
    };

    for (let i = 0; i < a.length; i++) {
        if (a[i].z == 0 || b[i].z == 0) {
            continue;
        }
        acc.Mul(acc, miller(b[i], a[i]));
    }
    return finalExponentiation(acc).IsOne();
}

function bn256G1() {
    return {
        x: 0,
        y: 0,
        z: 0,
        t: 0,
    };
}

function gfP12Mul() {
    // TBD
}

/**
 * Implements the Miller loop for calculating the Optimal Ate pairing.
 * @link http://cryptojedi.org/papers/dclxvi-20100714.pdf
 */
function miller(q, p) {
    // TBD
}

/**
 * Sets e to a+b and then returns e
 */
function bn256Add(e, a, b) {
    // TBD
}

/**
 * Sets e to g*k where g is the generator of the group and then returns e
 */
function bn256ScalarBaseMult(e, k) {
    // TBD
}

/**
 * Sets e to a*k and then returns e
 */
function bn256ScalarMult(e, a, k) {
    // TBD
}

/**
 * Sets e to -a and then returns e.
 */
function curveNeg(e, a) {
    // TBD
}
