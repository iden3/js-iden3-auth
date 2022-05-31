import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
} from '../protocol/models';
import { v4 as uuidv4 } from 'uuid';

import {
  AUTHORIZATION_REQUEST_MESSAGE_TYPE,
  MEDIA_TYPE_PLAIN,
} from '../protocol/constants';

import { verifyProof } from '../proofs/zk';
import { IKeyLoader } from 'loaders/key';
import { ISchemaLoader } from 'loaders/schema';
import { IStateResolver } from 'state/resolver';
import { Query } from '../circuits/query';
import { Circuits } from '../circuits/registry';
import { Token } from '@iden3/js-jwz';
import { TextDecoder } from 'util';

export function createAuthorizationRequest(
  reason: string,
  sender: string,
  callbackUrl: string,
): AuthorizationRequestMessage {
  return createAuthorizationRequestWithMessage(reason, '', sender, callbackUrl);
}
export function createAuthorizationRequestWithMessage(
  reason: string,
  message: string,
  sender: string,
  callbackUrl: string,
): AuthorizationRequestMessage {
  const uuid = uuidv4();
  const request: AuthorizationRequestMessage = {
    id: uuid,
    thid: uuid,
    from: sender,
    typ: MEDIA_TYPE_PLAIN,
    type: AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      reason: reason,
      message: message,
      callbackUrl: callbackUrl,
      scope: [],
    },
  };
  return request;
}

export class Verifier {
  private keyLoader: IKeyLoader;
  private schemaLoader: ISchemaLoader;
  private stateResolver: IStateResolver;

  constructor(
    keyLoader: IKeyLoader,
    schemaLoader: ISchemaLoader,
    stateResolver: IStateResolver,
  ) {
    this.keyLoader = keyLoader;
    this.schemaLoader = schemaLoader;
    this.stateResolver = stateResolver;
  }

  public async verifyAuthResponse(
    response: AuthorizationResponseMessage,
    request: AuthorizationRequestMessage,
  ) {
    if (request.body.message != response.body.message) {
      throw new Error(
        'message for siging from request is not presented in response',
      );
    }

    for (const proofRequest of request.body.scope) {
      const proofResp = response.body.scope.find(
        (proofResp) => proofResp.id === proofRequest.id,
      );
      if (!proofResp) {
        throw new Error(`proof is not given for requestId ${proofRequest.id}`);
      }
      const circuitId = proofResp.circuit_id;
      const key = await this.keyLoader.load(circuitId);
      if (!key) {
        throw new Error(
          `verification key is not found for circuit ${circuitId}`,
        );
      }
      let jsonKey = JSON.parse(new TextDecoder().decode(key));
      const isValid = await verifyProof(proofResp, jsonKey);
      if (!isValid) {
        throw new Error(
          `Proof with circuit id ${circuitId} and request id ${proofResp.id} is not valid`,
        );
      }

      const CircuitVerifier = Circuits.getCircuitPubSignals(circuitId);
      if (!CircuitVerifier) {
        throw new Error(`circuit ${circuitId} is not supported by the library`);
      }

      // verify query

      const verifier = new CircuitVerifier(proofResp.pub_signals);
      await verifier.verifyQuery(
        proofRequest.rules['query'] as Query,
        this.schemaLoader,
      );

      // verify states

      await verifier.verifyStates(this.stateResolver);
    }
  }

  public async verifyJWZ(tokenStr: string): Promise<Token> {
    const token = await Token.parse(tokenStr);

    const key = await this.keyLoader.load(token.circuitId);
    if (!key) {
      throw new Error(
        `verification key is not found for circuit ${token.circuitId}`,
      );
    }

    const isValid = token.verify(key);
    if (!isValid) {
      throw new Error(`zero-knowledge proof of jwz token is not valid`);
    }

    const CircuitVerifier = Circuits.getCircuitPubSignals(token.circuitId);

    if (!CircuitVerifier) {
      throw new Error(
        `circuit ${token.circuitId} is not supported by the library`,
      );
    }

    // outputs unmarshaller
    const verifier = new CircuitVerifier(token.zkProof.pub_signals);

    // state verification
    verifier.verifyStates(this.stateResolver);

    return token;
  }

  public async fullVerify(
    tokenStr: string,
    request: AuthorizationRequestMessage,
  ): Promise<AuthorizationResponseMessage> {
    const token = await this.verifyJWZ(tokenStr);

    const payload = token.getPayload();

    const response = JSON.parse(
      payload.toString(),
    ) as AuthorizationResponseMessage;

    await this.verifyAuthResponse(response, request);

    return response;
  }
}
