import 'snarkjs';
import { UserToken } from './circuits/token';

/* eslint-disable no-unused-vars */
const PROTOCOL_NAME = 'https://iden3-communication.io';
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';
const AUTHORIZATION_REQUEST_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-request/v1';

export const AUTH_CIRCUIT_ID = 'auth';
export const ZERO_KNOWLEDGE_PROOF_TYPE = 'zeroknowledge';

export async function verifyProofs(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message of type ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of proofs`;
    }
    for (const proof of message.data.scope) {
        switch (proof.type) {
        case ZERO_KNOWLEDGE_PROOF_TYPE:
            const isValid = zkpVerifyProof(proof);
            if (!isValid) {
                return `Proof with type ${proof.type} is not valid`;
            }
        default:
            return `Proof type ${proof.type} is not supported`;
        }
    }

    return null;
}

async function zkpVerifyProof(proof) {
    return await snarkjs.groth16.verify(proof.circuitData.verificationKey, proof.publicSignals, proof.proofData);
}

async function extractMetadata(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message of type ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of proofs`;
    }
    const token = new UserToken();
    for (const proof of message.data.scope) {
        switch (proof.type) {
        case ZERO_KNOWLEDGE_PROOF_TYPE:
            token.update(proof.circuitId, proof.metadata);
            break;
        default:
            return `Proof type ${proof.type} is not supported`;
        }
    }

    return null;
}

/**
 * Creates new authorization request message
 * @param {number} challenge
 * @param {string} aud
 * @param {string} callbackURL
 * @return {Object} AuthorizationMessageRequest
 */
export function createAuthorizationRequest(challenge, aud, callbackURL) {
    const message = {
        type: AUTHORIZATION_REQUEST_MESSAGE_TYPE,
        data: {
            callbackURL: callbackURL,
            audience: aud,
            scope: [],
        },
        message: null,
    };
    messageWithDefaultZKAuth(message, challenge);

    return message;
}

/**
 * Adds zkp proof to scope of request
 * @param {Object} message
 * @param {Object} proof
 */
export function messageWithZeroKnowledgeProofRequest(message, proof) {
    message.data.scope.push(proof);
}

/**
 * Adds authentication request to scope
 * @param {Object} message
 * @param {number} challenge
 */
export function messageWithDefaultZKAuth(message, challenge) {
    const rules = {
        challenge: challenge,
    };

    const authProofRequest = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitID: AUTH_CIRCUIT_ID,
        rules: rules,
    };

    messageWithZeroKnowledgeProofRequest(message, authProofRequest);
}
