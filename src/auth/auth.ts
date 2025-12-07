import { AuthPubSignals } from '@lib/circuits/auth';
import { Query } from '@lib/circuits/query';
import { v4 as uuidv4 } from 'uuid';

import { Resolvers } from '@lib/state/resolver';
import { Circuits, VerifyOpts } from '@lib/circuits/registry';
import { proving, ProvingMethodAlg, Token } from '@iden3/js-jwz';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  CircuitId,
  IPacker,
  JWSPacker,
  KMS,
  PackageManager,
  ProvingParams,
  PROTOCOL_CONSTANTS,
  VerificationHandlerFunc,
  VerificationParams,
  ZKPPacker,
  NativeProver,
  IZKProver,
  FSCircuitStorage,
  ICircuitStorage,
  cacheLoader,
  byteEncoder,
  JSONObject,
  verifyExpiresTime,
  parseAcceptProfile,
  getCircuitIdsWithSubVersions,
  ZeroKnowledgeProofRequest,
  getGroupedCircuitIdsWithSubVersions
} from '@0xpolygonid/js-sdk';
import { Resolvable } from 'did-resolver';
import { Options, DocumentLoader } from '@iden3/js-jsonld-merklization';
import path from 'path';
import { DID, getUnixTimestamp } from '@iden3/js-iden3-core';

/**
 * Options to pass to createAuthorizationRequest function
 * @public
 */
export type AuthorizationRequestCreateOptions = {
  accept?: string[];
  scope?: ZeroKnowledgeProofRequest[];
  expires_time?: Date;
};

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
  callbackUrl: string,
  opts?: AuthorizationRequestCreateOptions
): AuthorizationRequestMessage {
  return createAuthorizationRequestWithMessage(reason, '', sender, callbackUrl, opts);
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
  callbackUrl: string,
  opts?: AuthorizationRequestCreateOptions
): AuthorizationRequestMessage {
  const uuid = uuidv4();
  const request: AuthorizationRequestMessage = {
    id: uuid,
    thid: uuid,
    from: sender,
    typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
    type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    body: {
      accept: opts?.accept,
      reason: reason,
      message: message,
      callbackUrl: callbackUrl,
      scope: opts?.scope || []
    },
    created_time: getUnixTimestamp(new Date()),
    expires_time: opts?.expires_time ? getUnixTimestamp(opts.expires_time) : undefined
  };
  return request;
}
/**
 *  VerifierParams are params to pass init verifier that contain jsonld document loader options and
 *  options to verify the query
 */
export type VerifierParams = Options & {
  /* resolvers for state of the identities */
  stateResolver: Resolvers;
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
  packageManager: PackageManager;
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
  private stateResolver: Resolvers;

  private packageManager: PackageManager;
  private prover: IZKProver;
  private circuitStorage: ICircuitStorage;

  /**
   * Creates an instance of the Verifier.
   * @private
   * @param {Resolvers} resolvers - state resolvers instances
   * @param {VerifierSuiteParams} params - suite for verification
   */
  private constructor(stateResolver: Resolvers, params: VerifierSuiteParams) {
    this.schemaLoader = params.documentLoader;
    this.stateResolver = stateResolver;
    this.packageManager = params.packageManager;
    this.circuitStorage = params.circuitStorage;
    this.prover = params.prover;
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
        prover: new NativeProver(circuitStorage),
        packageManager: new PackageManager()
      };
      const verifier = new Verifier(params.stateResolver, params.suite);
      await verifier.initPackers(params.didDocumentResolver);
      return verifier;
    }
    return new Verifier(params.stateResolver, params.suite);
  }

  // setPackageManager sets the package manager for the Verifier.
  public setPackageManager(manager: PackageManager) {
    this.packageManager = manager;
  }

  // setPacker sets the custom packer manager for the Verifier.
  public setPacker(packer: IPacker) {
    return this.packageManager.registerPackers([packer]);
  }

  /**
    @deprecated, use setupAuthZKPPacker for AuthV2/AuthV3/ AuthV3_8_32 circuits support
    setupAuthV2ZKPPacker sets the custom packer manager for the Verifier.
  **/
  public async setupAuthV2ZKPPacker(circuitStorage: ICircuitStorage) {
    if (!circuitStorage) {
      throw new Error('circuit storage is not defined');
    }
    const authV2Set = await circuitStorage.loadCircuitData(CircuitId.AuthV2);

    if (!authV2Set.verificationKey) {
      throw new Error('verification key is not for authv2 circuit');
    }
    const mapKey = proving.provingMethodGroth16AuthV2Instance.methodAlg.toString();
    const provingParamMap: Map<string, ProvingParams> = new Map();

    const stateVerificationFn = async (
      circuitId: string,
      pubSignals: Array<string>
    ): Promise<boolean> => {
      if (circuitId !== CircuitId.AuthV2) {
        throw new Error(`CircuitId is not supported ${circuitId}`);
      }

      const verifier = new AuthPubSignals(pubSignals);
      await verifier.verifyStates(this.stateResolver);
      return true;
    };

    const verificationFn = new VerificationHandlerFunc(stateVerificationFn);

    const verificationParamMap: Map<string, VerificationParams> = new Map();
    verificationParamMap.set(mapKey, {
      key: authV2Set.verificationKey,
      verificationFn
    });

    const zkpPacker = new ZKPPacker(provingParamMap, verificationParamMap);
    return this.setPacker(zkpPacker);
  }

  // setupAuthZKPPacker sets the custom packer manager for the Verifier.
  public async setupAuthZKPPacker(circuitStorage: ICircuitStorage) {
    if (!circuitStorage) {
      throw new Error('circuit storage is not defined');
    }

    const circuitIds = getCircuitIdsWithSubVersions([CircuitId.AuthV2, CircuitId.AuthV3]);
    const verificationParamMap: Map<string, VerificationParams> = new Map();
    const provingParamMap: Map<string, ProvingParams> = new Map();

    const stateVerificationFn = async (
      circuitId: string,
      pubSignals: Array<string>
    ): Promise<boolean> => {
      if (!circuitIds.includes(circuitId as CircuitId)) {
        throw new Error(`CircuitId is not supported ${circuitId}`);
      }

      const verifier = new AuthPubSignals(pubSignals);
      await verifier.verifyStates(this.stateResolver);
      return true;
    };

    const verificationFn = new VerificationHandlerFunc(stateVerificationFn);

    for (const circuitId of circuitIds) {
      const authSet = await circuitStorage.loadCircuitData(circuitId);
      if (!authSet.verificationKey) {
        throw new Error(`verification key is not for ${circuitId} circuit`);
      }
      const methodAlg = new ProvingMethodAlg(
        PROTOCOL_CONSTANTS.AcceptJwzAlgorithms.Groth16,
        circuitId
      ).toString();
      verificationParamMap.set(methodAlg, {
        key: authSet.verificationKey,
        verificationFn
      });
    }

    const zkpPacker = new ZKPPacker(provingParamMap, verificationParamMap);
    return this.setPacker(zkpPacker);
  }

  // setupJWSPacker sets the JWS packer for the Verifier.
  public setupJWSPacker(kms: KMS, documentResolver: Resolvable) {
    const jwsPacker = new JWSPacker(kms, documentResolver);
    return this.setPacker(jwsPacker);
  }

  public verifyAuthRequest(request: AuthorizationRequestMessage, opts?: VerifyOpts) {
    if (!opts?.allowExpiredMessages) {
      verifyExpiresTime(request);
    }
    this.verifyProfile(request.type, request.body.accept);
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
    if (!opts?.allowExpiredMessages) {
      verifyExpiresTime(request);
    }
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

    const groupIdToLinkIdMap = new Map<number, { linkID: number; requestId: string }[]>();
    // group requests by query group id
    for (const proofRequest of requestScope) {
      const groupId = proofRequest.query.groupId as number;

      const proofResp = response.body.scope.find((resp) => resp.id === proofRequest.id);

      if (!proofResp) {
        if (proofRequest.optional) {
          continue;
        }
        throw new Error(`proof is not given for requestId ${proofRequest.id}`);
      }

      const circuitId = proofResp.circuitId as CircuitId;
      const circuitIds = getGroupedCircuitIdsWithSubVersions(circuitId);
      if (!circuitIds.includes(proofRequest.circuitId)) {
        throw new Error(
          `proof is not given for requested circuit expected: ${proofRequest.circuitId}, given ${circuitId}`
        );
      }

      const verifierInfo = Circuits.getCircuitPubSignals(circuitId);
      if (!verifierInfo) {
        throw new Error(`circuit ${circuitId} is not supported by the library`);
      }

      const params: JSONObject = proofRequest.params ?? {};
      params.verifierDid = DID.parse(request.from);

      // verify query
      const verifier = new verifierInfo.verifier(proofResp.pub_signals, verifierInfo.opts);

      const pubSignals = await verifier.verifyQuery(
        proofRequest.query as unknown as Query,
        this.schemaLoader,
        proofResp.vp,
        opts,
        params
      );

      // write linkId to the proof response
      const pubSig = pubSignals as unknown as { linkID?: number };

      if (pubSig.linkID && groupId) {
        groupIdToLinkIdMap.set(groupId, [
          ...(groupIdToLinkIdMap.get(groupId) ?? []),
          { linkID: pubSig.linkID, requestId: proofResp.id.toString() }
        ]);
      }
      // verify states

      await verifier.verifyStates(this.stateResolver, opts);

      if (!response.from) {
        throw new Error(`proof response doesn't contain from field`);
      }

      // verify id ownership
      await verifier.verifyIdOwnership(response.from, BigInt(proofResp.id));
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
   * verifies jwz token
   * @public
   * @param {string} tokenStr - token string
   * @param {VerifyOpts} opts - verification options
   *
   * @returns `Promise<Token>`
   */
  public async verifyJWZ(tokenStr: string, opts?: VerifyOpts): Promise<Token> {
    const token = await Token.parse(tokenStr);
    const key = (await this.circuitStorage.loadCircuitData(token.circuitId as CircuitId))
      .verificationKey;
    if (!key) {
      throw new Error(`verification key is not found for circuit ${token.circuitId}`);
    }

    const isValid = await token.verify(key);
    if (!isValid) {
      throw new Error(`zero-knowledge proof of jwz token is not valid`);
    }

    const verifierInfo = Circuits.getCircuitPubSignals(token.circuitId);

    if (!verifierInfo) {
      throw new Error(`circuit ${token.circuitId} is not supported by the library`);
    }

    // outputs unmarshaller
    const verifier = new verifierInfo.verifier(token.zkProof.pub_signals, verifierInfo.opts);

    // state verification
    await verifier.verifyStates(this.stateResolver, opts);

    return token;
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

    if (request.body.accept?.length) {
      const acceptedMediaTypes = request.body.accept.map(
        (accept) => parseAcceptProfile(accept).env
      );
      if (!acceptedMediaTypes.includes(msg.unpackedMediaType)) {
        throw new Error('response type is not in accept profiles of the request');
      }
    }

    const response = msg.unpackedMessage as AuthorizationResponseMessage;
    await this.verifyAuthResponse(response, request, opts);
    return response;
  }

  private async initPackers(didResolver?: Resolvable) {
    await this.setupAuthZKPPacker(this.circuitStorage);
    // set default jws packer if packageManager is not present in options but did document resolver is.
    if (didResolver) {
      this.setupJWSPacker(new KMS(), didResolver);
    }
  }

  private verifyProfile(messageType: string, profile?: string[] | undefined) {
    if (!profile?.length) {
      return;
    }
    const supportedMediaTypes: PROTOCOL_CONSTANTS.MediaType[] = [];
    for (const acceptProfile of profile) {
      const { env } = parseAcceptProfile(acceptProfile);
      if (this.packageManager.isProfileSupported(env, acceptProfile)) {
        supportedMediaTypes.push(env);
      }
    }

    if (!supportedMediaTypes.length) {
      throw new Error('no packer with profile which meets `accept` header requirements');
    }
  }
}
