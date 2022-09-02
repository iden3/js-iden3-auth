import { ZKPResponse } from '@lib/protocol/models';

import * as snarkjs from 'snarkjs';

export async function verifyProof(
  proofResp: ZKPResponse,
  verificationKey: object,
): Promise<boolean> {
  switch (proofResp.proof.protocol) {
    case 'groth16':
      return await snarkjs.groth16.verify(
        verificationKey,
        proofResp.pub_signals,
        proofResp.proof,
      );
    default:
      throw new Error(`${proofResp.proof.protocol} protocol is not supported`);
  }
}
