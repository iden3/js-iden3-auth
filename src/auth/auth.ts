import { Message, Scope } from './../models/models';
import { UserToken } from '../auth/token';
import { circuits } from '../circuits/constants';

import {
  ZERO_KNOWLEDGE_PROOF_TYPE,
  verifyProof,
  extractProofMetadata,
} from '../proofs/zk';

export const PROTOCOL_NAME = 'https://iden3-communication.io';
export const AUTHORIZATION_RESPONSE_MESSAGE_TYPE =
  PROTOCOL_NAME + '/authorization-response/v1';
export const AUTHORIZATION_REQUEST_MESSAGE_TYPE =
  PROTOCOL_NAME + '/authorization-request/v1';
export const CREDENTIAL_REQUEST_MESSAGE_TYPE =
  PROTOCOL_NAME + '/credential-fetch-request/v1';

export const AUTH_CIRCUIT_ID = 'auth';

export async function verifyProofs(message: Message): Promise<boolean> {
  if (
    ![
      AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      CREDENTIAL_REQUEST_MESSAGE_TYPE,
    ].includes(message.type)
  ) {
    throw new Error(`Message of type ${message.type} is not supported`);
  }
  if (!message.data || !message.data.scope) {
    throw new Error(`Message should contain list of proofs`);
  }
  for (const proof of message.data.scope) {
    switch (proof.type) {
      case ZERO_KNOWLEDGE_PROOF_TYPE:
        const isValid = await verifyProof(proof);
        if (!isValid) {
          throw new Error(`Proof with type ${proof.type} is not valid`);
        }
        break;
      default:
        throw new Error(`Proof type ${proof.type} is not supported`);
    }
  }

  return true;
}

export function extractMetadata(message: Message): UserToken {
  if (
    ![
      AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      CREDENTIAL_REQUEST_MESSAGE_TYPE,
    ].includes(message.type)
  ) {
    throw new Error(`Message of type ${message.type} is not supported`);
  }
  if (!message.data || !message.data.scope) {
    throw new Error(`Message should contain list of proofs`);
  }
  const token = new UserToken();
  for (const proof of message.data.scope) {
    switch (proof.type) {
      case ZERO_KNOWLEDGE_PROOF_TYPE:
        const metadata = extractProofMetadata(proof);
        token.update(proof.circuit_id, metadata);
        break;
      default:
        throw new Error(`Proof type ${proof.type} is not supported`);
    }
  }
  return token;
}

export function createAuthorizationRequest(
  challenge: number,
  aud: string,
  callbackUrl: string,
): Message {
  const message: Message = {
    type: AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    data: {
      callbackURL: callbackUrl,
      audience: aud,
      scope: [],
    },
  };
  messageWithDefaultZKAuth(message, challenge);

  return message;
}

export function messageWithZeroKnowledgeProofRequest(
  message: Message,
  proof: Scope,
): void {
  message.data.scope.push(proof);
}

export function messageWithDefaultZKAuth(
  message: Message,
  challenge: number,
): void {
  const rules = {
    challenge,
  };

  const authProofRequest = {
    type: ZERO_KNOWLEDGE_PROOF_TYPE,
    circuit_id: circuits.authCircuitId,
    rules,
  };

  messageWithZeroKnowledgeProofRequest(message, authProofRequest);
}
