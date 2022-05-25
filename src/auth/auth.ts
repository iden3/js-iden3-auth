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
import { Circuits } from 'circuits/registry';
import { Query } from 'circuits/query';

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

    for (const proofRequst of request.body.scope) {
      let proofResp = response.body.scope.find((proofResp) => {
        return proofResp.id == proofRequst.id;
      });
      if (!proofResp) {
        throw new Error(`proof is not given for requstid ${proofRequst.id}`);
      }
      let key = await this.keyLoader.load(proofResp.circuit_id);
      if (key.length == 0) {
        throw new Error(
          `verification key is not found for circuit ${proofResp.circuit_id}`,
        );
      }

      let jsonKey = JSON.parse(key.toString());

      const isValid = await verifyProof(proofResp, jsonKey);
      if (!isValid) {
        throw new Error(
          `Proof with circuit id ${proofResp.circuit_id} and request id ${proofResp.id} is not valid`,
        );
      }

      let circuitVerifier =  Circuits.getCircuitPubSignals(proofResp.circuit_id);
      if (!circuitVerifier){
          throw new Error(`circuit ${proofResp.circuit_id} is not supported by the library`);
      }

  
      // verify query
      
      circuitVerifier.unmarshall(proofResp.pub_signals)
      circuitVerifier.verifyQuery(proofRequst.rules["query"] as Query,this.schemaLoader)

      // verify states

      circuitVerifier.verifyStates(this.stateResolver)

    }
  }
  public async verifyJWZ(
    tokenStr: string,
    request: AuthorizationRequestMessage,
  ): Promise<MockToken> {
    // TODO : add jwz-parse

    var token =  new MockToken("auth","circuitId");

    let key = await this.keyLoader.load(token.circuitId);
    if (key.length == 0) {
      throw new Error(
        `verification key is not found for circuit ${token.circuitId}`,
      );
    }


     let circuitVerifier =  Circuits.getCircuitPubSignals(token.circuitId);
     if (!circuitVerifier){
         throw new Error(`circuit ${token.circuitId} is not supported by the library`);
     }
      
     // outputs unmarshaller

     circuitVerifier.unmarshall(token.pubsignals)
     
     // state verification

     circuitVerifier.verifyStates(this.stateResolver)

    return token;
  }
  public async fullVerify(
    tokenStr :string,
    request: AuthorizationRequestMessage,
  ) {
    
    let token = await this.verifyJWZ(tokenStr,request)

    let payload = token.getPayload()

    let response = JSON.parse(payload.toString()) as AuthorizationResponseMessage

    await this.verifyAuthResponse(response,request)

  }
}

export class MockToken {
  alg: string;
  circuitId: string;
  pubsignals :string [];

  constructor(alg: string, circuitId: string) {
    this.alg = alg;
    this.circuitId = circuitId;
  }

  getPayload() {
    return  Buffer.from("payload")
  }
}
