import 'snarkjs';

const PROTOCOL_NAME                       = 'https://iden3-communication.io'
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';

async function verifyProofs(message) {
    const verificationKey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message type of ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of scope`;
    }
    for (const scope of message.data.scope) {
        switch (scope.type) {
            case 'zeroknowledge':
                const isValid = zkpVerifyProof(scope.proofData, scope.publicSignals, verificationKey);
                if (!isValid) {
                    return `Proof with type ${scope.type} is not valid`;
                }
            default:
                return `Proof type ${scope.type} is not supported`;
        }
    }

    return null;
}

async function zkpVerifyProof(proofData, publicSignals, verificationKey) {
    return await snarkjs.groth16.verify(verificationKey, publicSignals, proofData);
}
