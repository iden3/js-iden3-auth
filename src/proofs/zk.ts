import { ZKPResponse } from '../protocol/models';

import * as snarkjs from 'snarkjs';

export async function verifyProof(
  proof: ZKPResponse,
  verificationKey: object,
): Promise<boolean> {
  switch (proof.proof_data.protocol) {
    case 'groth16':
      return await snarkjs.groth16.verify(
        verificationKey,
        proof.pub_signals,
        proof.proof_data,
      );
  }
}
