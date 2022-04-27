import { UserToken } from './token';
import { circuits } from './circuits/constants';

import {ZERO_KNOWLEDGE_PROOF_TYPE, verifyProof, extractProofMetadata} from './proofs/zk';


/* eslint-disable no-unused-vars */
const PROTOCOL_NAME = 'https://iden3-communication.io';
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';
const AUTHORIZATION_REQUEST_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-request/v1';


async function verifyProofs(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        throw new Error(`Message of type ${message.type} is not supported`);
    }
    if (!message.data || !message.data.scope) {
        throw new Error(`Message should contain list of proofs`);
    }
    for (const proof of message.data.scope) {
        switch (proof.type) {
        case ZERO_KNOWLEDGE_PROOF_TYPE:
            const isValid = verifyProof(proof);
            if (!isValid) {
                throw new Error(`Proof with type ${proof.type} is not valid`);
            }
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
async function extractMetadata(message) {
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
            let metadata = extractProofMetadata(proof)
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
function createAuthorizationRequest(challenge, aud, callbackURL) {
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
 * Adds authentication request to scope
 * @param {Object} message
 * @param {number} challenge
 */
function messageWithDefaultZKAuth(message, challenge) {
    const rules = {
        challenge: challenge,
    };

    const authProofRequest = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitID: circuits.AuthCircuitID,
        rules: rules,
    };

    message.data.scope.push(authProofRequest);
}
