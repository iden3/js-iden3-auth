
const PROTOCOL_NAME                       = 'https://iden3-communication.io'
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';
const AUTHORIZATION_REQUEST_MESSAGE_TYPE  = PROTOCOL_NAME + '/authorization-request/v1';

const AUTH_CIRCUIT_ID           = 'auth';
const ZERO_KNOWLEDGE_PROOF_TYPE = 'zeroknowledge';

async function verifyProofs(message) {
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

async function extractMetadata(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message of type ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of proofs`;
    }
    for (const proof of message.data.scope) {
        switch (proof.type) {
            case 'zeroknowledge':
                 // TODO: update token here.
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
function createAuthorizationRequest(challenge, aud, callbackURL) {
    const message = {
        type   : AUTHORIZATION_REQUEST_MESSAGE_TYPE,
        data   : {
            callbackURL: callbackURL,
            audience   : aud,
            scope      : [],
        },
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
        type     : ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitID: AUTH_CIRCUIT_ID,
        rules    : rules,
    };

    message.data.scope.push(authProofRequest);
}

/**
 * Adds zkp proof to scope of request
 * @param {Object} message
 * @param {Object} proof
 */
function messageWithZeroKnowledgeProofRequest(message, proof) {
    message.data.scope.push(proof);
}
