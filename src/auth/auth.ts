import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { Query } from '@lib/circuits/query';
import { v4 as uuidv4 } from 'uuid';

import { Resolvers } from '@lib/state/resolver';
import { Circuits, VerifyOpts } from '@lib/circuits/registry';
import { proving, Token } from '@iden3/js-jwz';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  CircuitId,
  IKeyLoader,
  IPacker,
  JWSPacker,
  KMS,
  PackageManager,
  ProvingParams,
  PROTOCOL_CONSTANTS,
  VerificationHandlerFunc,
  VerificationParams,
  ZKPPacker,
  ProofService
} from '@0xpolygonid/js-sdk';
import { Resolvable } from 'did-resolver';
import { Options, getDocumentLoader, DocumentLoader } from '@iden3/js-jsonld-merklization';

export function createAuthorizationRequest(
  reason: string,
  sender: string,
  callbackUrl: string
): AuthorizationRequestMessage {
  return createAuthorizationRequestWithMessage(reason, '', sender, callbackUrl);
}
export function createAuthorizationRequestWithMessage(
  reason: string,
  message: string,
  sender: string,
  callbackUrl: string
): AuthorizationRequestMessage {
  const uuid = uuidv4();
  const request: AuthorizationRequestMessage = {
    id: uuid,
    thid: uuid,
    from: sender,
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      reason: reason,
      message: message,
      callbackUrl: callbackUrl,
      scope: []
    }
  };
  return request;
}

export type VerificationOptions = Options & {
  packageManager?: PackageManager;
};

export class Verifier {
  private keyLoader: IKeyLoader;
  private schemaLoader: DocumentLoader;
  private stateResolver: Resolvers;
  private packageManager: PackageManager;
  private proofService: ProofService;

  private constructor(
    keyLoader: IKeyLoader,
    stateResolver: Resolvers,
    proofService: ProofService,
    opts?: VerificationOptions
  ) {
    this.keyLoader = keyLoader;
    this.proofService = proofService;
    this.schemaLoader = getDocumentLoader(opts as Options);
    this.stateResolver = stateResolver;
    this.packageManager = opts?.packageManager ?? new PackageManager();
  }

  static async newVerifier(
    keyLoader: IKeyLoader,
    proofService: ProofService,
    stateResolver: Resolvers,
    documentResolver: Resolvable,
    opts?: VerificationOptions
  ): Promise<Verifier> {
    const verifier = new Verifier(keyLoader, stateResolver, proofService, opts);
    await verifier.initPackers(documentResolver);
    return verifier;
  }

  async initPackers(documentResolver: Resolvable) {
    await this.setupAuthV2ZKPPacker();
    this.setupJWSPacker(null, documentResolver);
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
    const authV2Set = await this.keyLoader.load(CircuitId.AuthV2 + '/verification_key.json');
    const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
    const provingParamMap: Map<string, ProvingParams> = new Map();

    const stateVerificationFn = async (
      circuitId: string,
      pubSignals: Array<string>
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
      verificationFn
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
    opts?: VerifyOpts
  ) {
    if ((request.body.message ?? '') !== (response.body.message ?? '')) {
      throw new Error('message for signing from request is not presented in response');
    }

    for (const proofRequest of request.body.scope) {
      const proofResp = response.body.scope.find((proofResp) => proofResp.id === proofRequest.id);
      if (!proofResp) {
        throw new Error(`proof is not given for requestId ${proofRequest.id}`);
      }
      if (proofResp.circuitId !== proofRequest.circuitId) {
        throw new Error(
          `proof is not given for requested circuit expected: ${proofRequest.circuitId}, given ${proofResp.circuitId}`
        );
      }
      const circuitId = proofResp.circuitId;
      const isValid = await this.proofService.verifyProof(
        proofResp,
        circuitId as unknown as CircuitId
      );
      if (!isValid) {
        throw new Error(
          `Proof with circuit id ${circuitId} and request id ${proofResp.id} is not valid`
        );
      }

      const CircuitVerifier = Circuits.getCircuitPubSignals(circuitId);
      if (!CircuitVerifier) {
        throw new Error(`circuit ${circuitId} is not supported by the library`);
      }

      // verify query
      const verifier = new CircuitVerifier(proofResp.pub_signals);
      await verifier.verifyQuery(
        proofRequest.query as unknown as Query,
        this.schemaLoader,
        proofResp.vp as JSON,
        opts
      );

      // verify states

      await verifier.verifyStates(this.stateResolver, opts);

      // verify id ownership
      await verifier.verifyIdOwnership(response.from, BigInt(proofResp.id));
    }
  }

  public async verifyJWZ(tokenStr: string, opts?: VerifyOpts): Promise<Token> {
    const token = await Token.parse(tokenStr);
    const key = await this.keyLoader.load(token.circuitId + '/verification_key.json');
    if (!key) {
      throw new Error(`verification key is not found for circuit ${token.circuitId}`);
    }

    const isValid = await token.verify(key);
    if (!isValid) {
      throw new Error(`zero-knowledge proof of jwz token is not valid`);
    }

    const CircuitVerifier = Circuits.getCircuitPubSignals(token.circuitId);

    if (!CircuitVerifier) {
      throw new Error(`circuit ${token.circuitId} is not supported by the library`);
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
    opts?: VerifyOpts
  ): Promise<AuthorizationResponseMessage> {
    const msg = await this.packageManager.unpack(new TextEncoder().encode(tokenStr));
    const response = msg.unpackedMessage as AuthorizationResponseMessage;
    await this.verifyAuthResponse(response, request, opts);
    return response;
  }
}
