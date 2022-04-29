import { UserToken } from './token.js';
import { circuits } from './circuits/constants.js';

import { ZERO_KNOWLEDGE_PROOF_TYPE, verifyProof, extractProofMetadata } from './proofs/zk.js';

/* eslint-disable no-unused-vars */
export const PROTOCOL_NAME = 'https://iden3-communication.io';
export const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';
export const AUTHORIZATION_REQUEST_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-request/v1';

export const AUTH_CIRCUIT_ID = 'auth';

export async function verifyProofs(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        throw new Error(`Message of type ${message.type} is not supported`);
    }
    if (!message.data || !message.data.scope) {
        throw new Error(`Message should contain list of proofs`);
    }
    for (const proof of message.data.scope) {
        switch (proof.type) {
        case ZERO_KNOWLEDGE_PROOF_TYPE:
            const isValid = await verifyProof(proof);
            if (!isValid) {
                throw new Error(`Proof with type ${proof.type} is not valid`);
            }
            break;
        default:
            throw new Error(`Proof type ${proof.type} is not supported`);
        }
    }

    return null;
}

/**
 *
 * @param {Object} message
 * @return {UserToken}
 */
export function extractMetadata(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        throw new Error(`Message of type ${message.type} is not supported`);
    }
    if (!message.data || !message.data.scope) {
        throw new Error( `Message should contain list of proofs`);
    }
    const token = new UserToken();
    for (const proof of message.data.scope) {
        switch (proof.type) {
        case ZERO_KNOWLEDGE_PROOF_TYPE:
            const metadata = extractProofMetadata(proof);
            token.update(proof.circuitId, metadata);
            break;
        default:
            throw new Error( `Proof type ${proof.type} is not supported`);
        }
    }
    return token;
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
        circuitId: circuits.authCircuitId,
        rules: rules,
    };

    messageWithZeroKnowledgeProofRequest(message, authProofRequest);
}
