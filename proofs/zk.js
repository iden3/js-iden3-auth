

import { Circuits } from '../circuits/registry.js';
import * as snarkjs from 'snarkjs';

export const IDENTIFIER_ATTRIBUTE = 'user_identifier';
export const CHALLENGE_ATTRIBUTE = 'challenge';
export const STATE_ATTRIBUTE = 'user_state';
export const ZERO_KNOWLEDGE_PROOF_TYPE = 'zeroknowledge';

/**
 *  extractMetadata extracts metadata from proof with zeroknowledge type
 */
export function extractProofMetadata(proof) {
    if (proof.type !== ZERO_KNOWLEDGE_PROOF_TYPE) {
        throw new Error(`Proofs type ${metadata.type} is not zeroknowledge`);
    }
    const circuit = Circuits.getCircuit(proof.circuitId);
    if (!circuit) {
        throw new Error(`Circuit with id ${proof.circuitId} not found`);
    }
    const proofData = parsePublicSignals(proof.pubSignals, circuit.getPublicSignalsSchema());
    return proofData;
}

/**
 *  verifyProof verifies proof with zeroknowledge type
 */
export async function verifyProof(proof) {
    if (proof.type !== ZERO_KNOWLEDGE_PROOF_TYPE) {
        throw new Error(`Proofs type ${proof.type} is not zeroknowledge`);
    }
    const circuit = Circuits.getCircuit(proof.circuitId);
    if (!circuit) {
        throw new Error(`Circuit with id ${proof.circuitId} not found`);
    }

    return await snarkjs.groth16.verify(circuit.getVerificationKey(), proof.pubSignals, proof.proofData);
}

/**
 *
 * @param {[]string} signals
 * @param {[]byte} schema
 * @return {ProofMetadata}
 */
function parsePublicSignals(signals, schema) {
    const proofMetadata = { };

    const metaData = JSON.parse(schema);

    const identifierIndex = metaData[IDENTIFIER_ATTRIBUTE];
    if (!identifierIndex) {
        throw new Error('No user identifier attribute in provided proof');
    }
    const stateIndex = metaData[STATE_ATTRIBUTE];
    if (stateIndex) {
        proofMetadata.authData.userState = signals[stateIndex];
    }
    const challengeIndex = metaData[CHALLENGE_ATTRIBUTE];
    if (!challengeIndex) {
        throw new Error('No user challenge attribute in provided proof');
    }

    proofMetadata.authData.userIdentifier = convertID(signals[identifierIndex]);

    proofMetadata.authData.authenticationChallenge = signals[challengeIndex];

    Object.keys(metaData)
        .filter((k) => ![IDENTIFIER_ATTRIBUTE, CHALLENGE_ATTRIBUTE].includes(k))
        .forEach((k) => proofMetadata.AdditionalData[k] = signals[metaData[k]]);

    return proofMetadata;
}

