import { v4 as uuidv4 } from 'uuid';

import { Resolvers } from '@lib/state/resolver';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  IPacker,
  JWSPacker,
  KMS,
  PackageManager,
  PROTOCOL_CONSTANTS,
  NativeProver,
  IZKProver,
  FSCircuitStorage,
  ICircuitStorage,
  cacheLoader,
  byteEncoder,
  ZeroKnowledgeProofRequest,
  VerifyContext,
  PubSignalsVerifier,
  IStateStorage,
  ProofQuery,
  VerifyOpts,
  ZeroKnowledgeProofResponse,
  IPackageManager
} from '@0xpolygonid/js-sdk';
import { Resolvable } from 'did-resolver';
import { Options, DocumentLoader } from '@iden3/js-jsonld-merklization';
import path from 'path';
import { DID } from '@iden3/js-iden3-core';

/**
 *  createAuthorizationRequest is a function to create protocol authorization request
 * @param {string} reason - reason to request proof
 * @param {string} sender - sender did
 * @param {string} callbackUrl - callback that user should use to send response
 * @returns `Promise<AuthorizationRequestMessage>`
 */
export function createAuthorizationRequest(
  reason: string,
  sender: string,
  callbackUrl: string
): AuthorizationRequestMessage {
  return createAuthorizationRequestWithMessage(reason, '', sender, callbackUrl);
}
/**
 *  createAuthorizationRequestWithMessage is a function to create protocol authorization request with explicit message to sign
 * @param {string} reason - reason to request proof
 * @param {string} message - message to sign in the response
 * @param {string} sender - sender did
 * @param {string} callbackUrl - callback that user should use to send response
 * @returns `Promise<AuthorizationRequestMessage>`
 */
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
/**
 *  VerifierParams are params to pass init verifier that contain jsonld document loader options and
 *  options to verify the query
 */
export type VerifierParams = Options & {
  /* state storage for state of the identities */
  stateStorage: IStateStorage;
  /* package manager */
  packageManager: IPackageManager;
  /* didDocumentResolver to init default jws packer */
  didDocumentResolver?: Resolvable;
  /* circuitsDir - directory where circuits files are stored (default - 'circuits') */
  circuitsDir?: string;
  /* suite - optional suite with prover, circuit storage, package manager and document loader */
  suite?: VerifierSuiteParams;
};

/**
 *  VerifierSuiteParams are custom defined prover, circuit storage, package manager and document loader
 */
export interface VerifierSuiteParams {
  documentLoader: DocumentLoader;
  circuitStorage: ICircuitStorage;
  prover: IZKProver;
}
/**
 *
 * Verifier is responsible for verification of JWZ / JWS packed messages with zero-knowledge proofs inside.
 *
 * @public
 * @class Verifier
 */
export class Verifier {
  private schemaLoader: DocumentLoader;

  private packageManager: IPackageManager;
  private prover: IZKProver;
  private readonly _pubSignalsVerifier: PubSignalsVerifier;

  // private readonly _authHandler: AuthHandler;

  /**
   * Creates an instance of the Verifier.
   * @private
   * @param {Resolvers} resolvers - state resolvers instances
   * @param {VerifierSuiteParams} params - suite for verification
   */
  private constructor(
    stateStorage: IStateStorage,
    packageManager: IPackageManager,
    params: VerifierSuiteParams
  ) {
    this.schemaLoader = params.documentLoader;
    this.packageManager = packageManager;
    this.prover = params.prover;

    this._pubSignalsVerifier = new PubSignalsVerifier(this.schemaLoader, stateStorage);
  }

  /**
   * Creates an instance of the Verifier.
   * @public
   * @param {VerifierParams} params - params to init verifier
   * @returns `Promise<Verifier>`
   */
  static async newVerifier(params: VerifierParams): Promise<Verifier> {
    if (!params.suite) {
      const documentLoader = (params as Options).documentLoader ?? cacheLoader(params as Options);
      const dirname = params?.circuitsDir ?? path.join(process.cwd(), 'circuits');
      const circuitStorage = new FSCircuitStorage({ dirname });
      params.suite = {
        documentLoader,
        circuitStorage,
        prover: new NativeProver(circuitStorage)
      };
      const verifier = new Verifier(params.stateStorage, params.packageManager, params.suite);
      return verifier;
    }
    return new Verifier(params.stateStorage, params.packageManager, params.suite);
  }

  // setPackageManager sets the package manager for the Verifier.
  public setPackageManager(manager: PackageManager) {
    this.packageManager = manager;
  }

  // setPacker sets the custom packer manager for the Verifier.
  public setPacker(packer: IPacker) {
    return this.packageManager.registerPackers([packer]);
  }

  // setupJWSPacker sets the JWS packer for the Verifier.
  public setupJWSPacker(kms: KMS, documentResolver: Resolvable) {
    const jwsPacker = new JWSPacker(kms, documentResolver);
    return this.setPacker(jwsPacker);
  }

  public verifyAuthRequest(request: AuthorizationRequestMessage) {
    const groupIdValidationMap: { [k: string]: ZeroKnowledgeProofRequest[] } = {};
    const requestScope = request.body.scope;
    for (const proofRequest of requestScope) {
      const groupId = proofRequest.query.groupId as number;
      if (groupId) {
        const existingRequests = groupIdValidationMap[groupId] ?? [];

        //validate that all requests in the group have the same schema, issuer and circuit
        for (const existingRequest of existingRequests) {
          if (existingRequest.query.type !== proofRequest.query.type) {
            throw new Error(`all requests in the group should have the same type`);
          }

          if (existingRequest.query.context !== proofRequest.query.context) {
            throw new Error(`all requests in the group should have the same context`);
          }

          const allowedIssuers = proofRequest.query.allowedIssuers as string[];
          const existingRequestAllowedIssuers = existingRequest.query.allowedIssuers as string[];
          if (
            !(
              allowedIssuers.includes('*') ||
              allowedIssuers.every((issuer) => existingRequestAllowedIssuers.includes(issuer))
            )
          ) {
            throw new Error(`all requests in the group should have the same issuer`);
          }
        }
        groupIdValidationMap[groupId] = [...(groupIdValidationMap[groupId] ?? []), proofRequest];
      }
    }
  }

  /**
   * verifies zero knowledge proof response according to the proof request
   * @public
   * @param {AuthorizationResponseMessage} response - auth protocol response
   * @param {AuthorizationRequestMessage} proofRequest - auth protocol request
   * @param {VerifyOpts} opts - verification options
   *
   * @returns `Promise<void>`
   */
  public async verifyAuthResponse(
    response: AuthorizationResponseMessage,
    request: AuthorizationRequestMessage,
    opts?: VerifyOpts
  ) {
    if ((request.body.message ?? '') !== (response.body.message ?? '')) {
      throw new Error('message for signing from request is not presented in response');
    }

    if (request.from !== response.to) {
      throw new Error(
        `sender of the request is not a target of response - expected ${request.from}, given ${response.to}`
      );
    }

    this.verifyAuthRequest(request);
    const requestScope = request.body.scope;

    if (!response.from) {
      throw new Error(`proof response doesn't contain from field`);
    }

    const groupIdToLinkIdMap = new Map<number, { linkID: number; requestId: number }[]>();
    // group requests by query group id
    for (const proofRequest of requestScope) {
      const groupId = proofRequest.query.groupId as number;

      const proofResp = response.body.scope.find(
        (resp: ZeroKnowledgeProofResponse) => resp.id === proofRequest.id
      );
      if (!proofResp) {
        throw new Error(`proof is not given for requestId ${proofRequest.id}`);
      }

      const circuitId = proofResp.circuitId;
      if (circuitId !== proofRequest.circuitId) {
        throw new Error(
          `proof is not given for requested circuit expected: ${proofRequest.circuitId}, given ${circuitId}`
        );
      }

      const proofValid = await this.prover.verify(proofResp, proofResp.circuitId);
      if (!proofValid) {
        throw Error(
          `Proof with circuit id ${proofResp.circuitId} and request id ${proofResp.id} is not valid`
        );
      }

      const params = proofRequest.params ?? {};
      params.verifierDid = DID.parse(request.from);
      const verifyContext: VerifyContext = {
        pubSignals: proofResp.pub_signals,
        query: proofRequest.query as unknown as ProofQuery,
        verifiablePresentation: proofResp.vp as JSON,
        sender: response.from,
        challenge: BigInt(proofResp.id),
        opts: opts,
        params: params
      };
      const pubSignals = await this._pubSignalsVerifier.verify(proofResp.circuitId, verifyContext);
      const linkID = (pubSignals as unknown as { linkID?: number }).linkID;

      if (linkID && groupId) {
        groupIdToLinkIdMap.set(groupId, [
          ...(groupIdToLinkIdMap.get(groupId) ?? []),
          { linkID: linkID as unknown as number, requestId: proofResp.id }
        ]);
      }
    }

    // verify grouping links
    for (const [groupId, metas] of groupIdToLinkIdMap.entries()) {
      // check that all linkIds are the same
      if (metas.some((meta) => meta.linkID !== metas[0].linkID)) {
        throw new Error(
          `Link id validation failed for group ${groupId}, request linkID to requestIds info: ${JSON.stringify(
            metas
          )}`
        );
      }
    }
  }

  /**
   * perform both verification of jwz / jws token and authorization request message
   * @public
   * @param {string} tokenStr - token string
   * @param {AuthorizationRequestMessage} request - auth protocol request
   * @param {VerifyOpts} opts - verification options
   *
   * @returns `Promise<AuthorizationResponseMessage>`
   */
  public async fullVerify(
    tokenStr: string,
    request: AuthorizationRequestMessage,
    opts?: VerifyOpts
  ): Promise<AuthorizationResponseMessage> {
    const msg = await this.packageManager.unpack(byteEncoder.encode(tokenStr));
    const response = msg.unpackedMessage as AuthorizationResponseMessage;
    await this.verifyAuthResponse(response, request, opts);
    return response;
  }
}
