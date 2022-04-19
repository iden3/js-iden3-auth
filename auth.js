import 'snarkjs';

async function verifyProofs(message) {
    const verificationKey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });
    for (const scope in message.data.scope) {
        const error = verifyProof(scope.proofData, scope.publicSignals, verificationKey);
        if (error) {
            return error;
        }
    }

    return null;
}

async function verifyProof(proofData, publicSignals, verificationKey) {
    const proofType = '';
    switch (proofType) {
        case 'zeroknowledge':
            const res = await snarkjs.groth16.verify(verificationKey, publicSignals, proofData);
            return res ? null : `Proof with type ${proofType} is not valid`;
        default:
            return `Proof type ${proofType} is not supported`;
    }
}
