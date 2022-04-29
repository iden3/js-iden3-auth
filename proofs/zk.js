
import { Id } from '../core/id.js';
import { Core } from '../core/core.js';
import { Circuits } from '../circuits/registry.js';
import { AuthenticationMetadata, ProofMetadata } from '../proofs/metadata.js';
import * as snarkjs from 'snarkjs';

export const IDENTIFIER_ATTRIBUTE = 'userID';
export const CHALLENGE_ATTRIBUTE = 'challenge';
export const STATE_ATTRIBUTE = 'userState';
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
    const metaData = JSON.parse(schema);
    const identifierIndex = metaData[IDENTIFIER_ATTRIBUTE];
    if (identifierIndex === undefined) {
        throw new Error('No user identifier attribute in provided proof');
    }
    const stateIndex = metaData[STATE_ATTRIBUTE];
    const userState = stateIndex ? signals[stateIndex] : null;
    const challengeIndex = metaData[CHALLENGE_ATTRIBUTE];
    if (challengeIndex === undefined) {
        throw new Error('No user challenge attribute in provided proof');
    }

    const authData = new AuthenticationMetadata(
        convertId(signals[identifierIndex]),
        userState,
        signals[challengeIndex],
    );
    const proofMetadata = new ProofMetadata(authData);

    Object.keys(metaData)
        .filter((k) => ![IDENTIFIER_ATTRIBUTE, CHALLENGE_ATTRIBUTE].includes(k))
        .forEach((k) => proofMetadata.additionalData[k] = signals[metaData[k]]);

    return proofMetadata;
}

function convertId(id) {
    const bytes = Core.intToBytes(BigInt(id));
    return Id.idFromBytes(bytes).string();
}
