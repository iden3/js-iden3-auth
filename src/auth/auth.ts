import {
  AuthorizationRequestMessage,
  AuthorizationResponseBody,
  Message,
  ZKPRequest,
} from '../protocol/models';
import {
  AUTHORIZATION_REQUEST_MESSAGE_TYPE,
  AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
  CREDENTIAL_REQUEST_MESSAGE_TYPE,
} from '../protocol/constants';

import { UserToken } from '../auth/token';
import { circuits } from '../circuits/constants';

import { verifyProof, extractProofMetadata } from '../proofs/zk';

export async function verifyProofs(message: Message): Promise<boolean> {
  if (
    ![
      AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      CREDENTIAL_REQUEST_MESSAGE_TYPE,
    ].includes(message.type)
  ) {
    throw new Error(`Message of type ${message.type} is not supported`);
  }
  const msgData = message.data as AuthorizationResponseBody;
  if (!msgData || !msgData.scope) {
    throw new Error(`Message should contain list of proofs`);
  }
  for (const proof of msgData.scope) {
    const isValid = await verifyProof(proof);
    if (!isValid) {
      throw new Error(
        `Proof with circuit id  ${proof.circuit_id} is not valid`,
      );
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
  const msgData = message.data as AuthorizationResponseBody;
  if (!msgData || !msgData.scope) {
    throw new Error(`Message should contain list of proofs`);
  }
  const token = new UserToken();
  for (const proof of msgData.scope) {
    const metadata = extractProofMetadata(proof);
    token.update(proof.circuit_id, metadata);
  }
  return token;
}

export function createAuthorizationRequest(
  challenge: number,
  aud: string,
  callbackUrl: string,
): AuthorizationRequestMessage {
  const message: AuthorizationRequestMessage = {
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
  message: AuthorizationRequestMessage,
  proof: ZKPRequest,
): void {
  message.data.scope.push(proof);
}

export function messageWithDefaultZKAuth(
  message: AuthorizationRequestMessage,
  challenge: number,
): void {
  const rules = {
    challenge,
  };

  const authProofRequest: ZKPRequest = {
    circuit_id: circuits.authCircuitId,
    rules,
  };

  messageWithZeroKnowledgeProofRequest(message, authProofRequest);
}
