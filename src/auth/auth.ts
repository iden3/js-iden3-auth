import { v4 as uuidv4 } from 'uuid';

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
  PubSignalsVerifier,
  IStateStorage,
  VerifyOpts,
  IPackageManager,
  IProofService,
  AuthHandler
} from '@0xpolygonid/js-sdk';
import { Resolvable } from 'did-resolver';
import { Options, DocumentLoader } from '@iden3/js-jsonld-merklization';
import path from 'path';

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
  /* proof service */
  proofService: IProofService;
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
  private _authHandler: AuthHandler;

  /**
   * Creates an instance of the Verifier.
   * @param {Resolvers} resolvers - state resolvers instances
   * @param {VerifierSuiteParams} params - suite for verification
   */
 constructor(
    private _packageManager: IPackageManager,
    private readonly _proofService: IProofService,
  ) {
    this._authHandler = new AuthHandler(_packageManager, _proofService);
  }

  // setPackageManager sets the package manager for the Verifier.
  public setPackageManager(manager: PackageManager) {
    this._packageManager = manager;
    this._authHandler = new AuthHandler(manager, this._proofService);
  }

  // setPacker sets the custom packer manager for the Verifier.
  public setPacker(packer: IPacker) {
    return this._packageManager.registerPackers([packer]);
  }

  // setupJWSPacker sets the JWS packer for the Verifier.
  public setupJWSPacker(kms: KMS, documentResolver: Resolvable) {
    const jwsPacker = new JWSPacker(kms, documentResolver);
    return this.setPacker(jwsPacker);
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
    return this._authHandler.handleAuthorizationResponse(response, request, opts);
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
    const msg = await this._packageManager.unpack(byteEncoder.encode(tokenStr));
    const response = msg.unpackedMessage as AuthorizationResponseMessage;
    await this.verifyAuthResponse(response, request, opts);
    return response;
  }
}
