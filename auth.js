import 'snarkjs';

async function verifyProofs(message) {
    const verificationKey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });
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
