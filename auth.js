
const PROTOCOL_NAME                       = 'https://iden3-communication.io'
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';
const AUTHORIZATION_REQUEST_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-request/v1';



async function verifyProofs(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message of type ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of proofs`;
    }
    for (const proof of message.data.scope) {
        switch (proof.type) {
            case 'zeroknowledge':
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


