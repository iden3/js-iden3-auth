import 'snarkjs';

const PROTOCOL_NAME                       = 'https://iden3-communication.io'
const AUTHORIZATION_RESPONSE_MESSAGE_TYPE = PROTOCOL_NAME + '/authorization-response/v1';

async function verifyProofs(message) {
    if (message.type !== AUTHORIZATION_RESPONSE_MESSAGE_TYPE) {
        return `Message type of ${message.type} is not supported`;
    }
    if (!message.data || !message.data.scope) {
        return `Message should contain list of ZKP proofs`;
    }
    for (const zkpProof of message.data.scope) {
        switch (zkpProof.type) {
            case 'zeroknowledge':
                const isValid = zkpVerifyProof(zkpProof.proofData, zkpProof.publicSignals, zkpProof.circuitData.verificationKey);
                if (!isValid) {
                    return `Proof with type ${zkpProof.type} is not valid`;
                }
            default:
                return `Proof type ${zkpProof.type} is not supported`;
        }
    }

    return null;
}

async function zkpVerifyProof(proofData, publicSignals, verificationKey) {
    return await snarkjs.groth16.verify(verificationKey, publicSignals, proofData);
}
