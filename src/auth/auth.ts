import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { Query } from '@lib/circuits/query';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
} from '@lib/protocol/models';
import { v4 as uuidv4 } from 'uuid';

import {
  AUTHORIZATION_REQUEST_MESSAGE_TYPE,
  MEDIA_TYPE_PLAIN,
} from '@lib/protocol/constants';

import { verifyProof } from '@lib/proofs/zk';
import { IKeyLoader } from '@lib/loaders/key';
import { ISchemaLoader } from '@lib/loaders/schema';
import { Resolvers } from '@lib/state/resolver';
import { Circuits, VerifyOpts } from '@lib/circuits/registry';
import { proving, Token } from '@iden3/js-jwz';
import {
  CircuitId,
  IPacker,
  JWSPacker,
  KMS,
  PackageManager,
  ProvingParams,
  resolveDIDDocument,
  VerificationHandlerFunc,
  VerificationParams,
  ZKPPacker,
} from '@0xpolygonid/js-sdk';
import { Resolvable } from 'did-resolver';

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
  private stateResolver: Resolvers;
  private packageManager: PackageManager;

  constructor(
    keyLoader: IKeyLoader,
    schemaLoader: ISchemaLoader,
    stateResolver: Resolvers,
    packageManager: PackageManager = new PackageManager(),
  ) {
    this.keyLoader = keyLoader;
    this.schemaLoader = schemaLoader;
    this.stateResolver = stateResolver;
    this.packageManager = packageManager;
  }

  async initPackers() {
    await this.setupAuthV2ZKPPacker();
    this.setupJWSPacker(null, { resolve: resolveDIDDocument });
  }

  // setPackageManager sets the package manager for the Verifier.
  public setPackageManager(manager: PackageManager) {
    this.packageManager = manager;
  }

  // setPacker sets the custom packer manager for the Verifier.
  public setPacker(packer: IPacker) {
    return this.packageManager.registerPackers([packer]);
  }

  // setupAuthV2ZKPPacker sets the custom packer manager for the Verifier.
  public async setupAuthV2ZKPPacker() {
    const authV2Set = await this.keyLoader.load(CircuitId.AuthV2);
    const mapKey =
      proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
    const provingParamMap: Map<string, ProvingParams> = new Map();

    const stateVerificationFn = async (
      circuitId: string,
      pubSignals: Array<string>,
    ): Promise<boolean> => {
      if (circuitId !== CircuitId.AuthV2) {
        throw new Error(`CircuitId is not supported ${circuitId}`);
      }

      const verifier = new AuthPubSignalsV2(pubSignals);
      await verifier.verifyStates(this.stateResolver);
      return true;
    };

    const verificationFn = new VerificationHandlerFunc(stateVerificationFn);

    const verificationParamMap: Map<string, VerificationParams> = new Map();
    verificationParamMap.set(mapKey, {
      key: authV2Set,
      verificationFn,
    });

    const zkpPacker = new ZKPPacker(provingParamMap, verificationParamMap);
    return this.setPacker(zkpPacker);
  }

  // setupJWSPacker sets the JWS packer for the Verifier.
  public setupJWSPacker(kms: KMS, documentResolver: Resolvable) {
    const jwsPacker = new JWSPacker(kms, documentResolver);
    return this.setPacker(jwsPacker);
  }

  public async verifyAuthResponse(
    response: AuthorizationResponseMessage,
    request: AuthorizationRequestMessage,
    opts?: VerifyOpts,
  ) {
    if ((request.body.message ?? '') !== (response.body.message ?? '')) {
      throw new Error(
        'message for signing from request is not presented in response',
      );
    }

    for (const proofRequest of request.body.scope) {
      const proofResp = response.body.scope.find(
        (proofResp) => proofResp.id === proofRequest.id,
      );
      if (!proofResp) {
        throw new Error(`proof is not given for requestId ${proofRequest.id}`);
      }
      if (proofResp.circuitId !== proofRequest.circuitId) {
        throw new Error(
          `proof is not given for requested circuit expected: ${proofRequest.circuitId}, given ${proofResp.circuitId}`,
        );
      }
      const circuitId = proofResp.circuitId;
      const key = await this.keyLoader.load(circuitId);
      if (!key) {
        throw new Error(
          `verification key is not found for circuit ${circuitId}`,
        );
      }
      const jsonKey = JSON.parse(new TextDecoder().decode(key));
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
        proofRequest.query as Query,
        this.schemaLoader,
        proofResp.vp,
      );

      // verify states

      await verifier.verifyStates(this.stateResolver, opts);

      // verify id ownership
      await verifier.verifyIdOwnership(response.from, BigInt(proofResp.id));
    }
  }

  public async verifyJWZ(tokenStr: string, opts?: VerifyOpts): Promise<Token> {
    const token = await Token.parse(tokenStr);
    const key = await this.keyLoader.load(token.circuitId);
    if (!key) {
      throw new Error(
        `verification key is not found for circuit ${token.circuitId}`,
      );
    }

    const isValid = await token.verify(key);
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
    await verifier.verifyStates(this.stateResolver, opts);

    return token;
  }

  public async fullVerify(
    tokenStr: string,
    request: AuthorizationRequestMessage,
    opts?: VerifyOpts,
  ): Promise<AuthorizationResponseMessage> {
    const msg = await this.packageManager.unpack(
      new TextEncoder().encode(tokenStr),
    );
    const response = msg.unpackedMessage as AuthorizationResponseMessage;
    await this.verifyAuthResponse(response, request, opts);
    return response;
  }
}
