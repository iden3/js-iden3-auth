import 'snarkjs';

async function calculateProof() {

    const {proof, publicSignals} =  await snarkjs.groth16.fullProve(
        {a: 3, b: 11},
        'test/circuit/circuit.wasm',
        'test/circuit/circuit_final.zkey'
    );

    const vkey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });

    const res = await snarkjs.groth16.verify(vkey, publicSignals, proof);

    console.log(res);
}
