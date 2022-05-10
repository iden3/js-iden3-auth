import { AuthenticationMetadata, ZKPResponse } from '../protocol/models';

import { Id } from '../core/id';
import { Core } from '../core/core';
import { Circuits } from '../circuits/registry';
import * as snarkjs from 'snarkjs';
import { ProofMetadata } from '../protocol/models';

export const IDENTIFIER_ATTRIBUTE = 'userID';
export const CHALLENGE_ATTRIBUTE = 'challenge';
export const STATE_ATTRIBUTE = 'userState';

export function extractProofMetadata(proof: ZKPResponse): ProofMetadata {
  const circuit = Circuits.getCircuit(proof.circuit_id);
  if (!circuit) {
    throw new Error(`Circuit with id ${proof.circuit_id} not found`);
  }
  const proofData = parsePublicSignals(
    proof.pub_signals,
    circuit.getPublicSignalsSchema(),
  );
  return proofData;
}

export async function verifyProof(proof: ZKPResponse): Promise<boolean> {
  const circuit = Circuits.getCircuit(proof.circuit_id);
  if (!circuit) {
    throw new Error(`Circuit with id ${proof.circuit_id} not found`);
  }

  return await snarkjs.groth16.verify(
    circuit.getVerificationKey(),
    proof.pub_signals,
    proof.proof_data,
  );
}

function parsePublicSignals(signals: string[], schema: string) {
  const metaData = JSON.parse(schema);
  const identifierIndex = metaData[IDENTIFIER_ATTRIBUTE];
  if (identifierIndex === undefined) {
    throw new Error('No user identifier attribute in provided proof');
  }
  const stateIndex = metaData[STATE_ATTRIBUTE];
  const userState = stateIndex ? signals[stateIndex] : null;
  const challengeIndex = metaData[CHALLENGE_ATTRIBUTE];
  if (challengeIndex === undefined) {
    throw new Error('No user challenge attribute in provided proof');
  }

  const authData: AuthenticationMetadata = {
    userIdentifier: convertId(signals[identifierIndex]),
    userState,
    authenticationChallenge: parseInt(signals[challengeIndex]),
  };
  const proofMetadata = new ProofMetadata(authData);

  Object.keys(metaData)
    .filter((k) => ![IDENTIFIER_ATTRIBUTE, CHALLENGE_ATTRIBUTE].includes(k))
    .forEach((k) => (proofMetadata.additionalData[k] = signals[metaData[k]]));

  return proofMetadata;
}

function convertId(id: string): string {
  const bytes: Uint8Array = Core.intToBytes(BigInt(id));
  return Id.idFromBytes(bytes).string();
}
