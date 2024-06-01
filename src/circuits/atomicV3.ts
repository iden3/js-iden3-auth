import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { ClaimOutputs, Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState, getResolverByID } from '@lib/circuits/common';
import { DID, getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { DocumentLoader, getDocumentLoader } from '@iden3/js-jsonld-merklization';
import {
  AtomicQueryV3PubSignals,
  BaseConfig,
  byteEncoder,
  checkCircuitOperator,
  checkQueryRequest,
  CircuitId,
  JSONObject,
  Operators,
  parseQueriesMetadata,
  ProofType,
  validateDisclosureNativeSDSupport,
  validateEmptyCredentialSubjectNoopNativeSupport,
  validateOperators,
  verifyFieldValueInclusionNativeExistsSupport
} from '@0xpolygonid/js-sdk';
import { JsonLd } from 'jsonld/jsonld-spec';

const valuesSize = 64;
const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

/**
 * Verifies the public signals for the AtomicQueryV3 circuit.
 * @beta
 */
export class AtomicQueryV3PubSignalsVerifier
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  pubSignals = new AtomicQueryV3PubSignals();

  constructor(pubSignals: string[]) {
    super();
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals))
    );

    this.userId = this.pubSignals.userID;
    this.challenge = this.pubSignals.requestID;
  }

  async verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts,
    params?: JSONObject
  ): Promise<BaseConfig> {
    const outs: ClaimOutputs = {
      issuerId: this.pubSignals.issuerID,
      schemaHash: this.pubSignals.claimSchema,
      slotIndex: this.pubSignals.slotIndex,
      operator: this.pubSignals.operator,
      value: this.pubSignals.value,
      timestamp: this.pubSignals.timestamp,
      merklized: this.pubSignals.merklized,
      claimPathKey: this.pubSignals.claimPathKey,
      valueArraySize: valuesSize,
      isRevocationChecked: this.pubSignals.isRevocationChecked,
      operatorOutput: this.pubSignals.operatorOutput
    };

    if (!query.type) {
      throw new Error(`proof query type is undefined`);
    }

    const loader = schemaLoader ?? getDocumentLoader();

    // validate schema
    let context: JsonLd;
    try {
      context = (await loader(query.context ?? '')).document;
    } catch (e) {
      throw new Error(`can't load schema for request query`);
    }

    const queriesMetadata = await parseQueriesMetadata(
      query.type,
      JSON.stringify(context),
      query.credentialSubject as JSONObject,
      {
        documentLoader: loader
      }
    );

    const circuitId = CircuitId.AtomicQueryV3;
    await checkQueryRequest(
      query,
      queriesMetadata,
      context,
      outs,
      CircuitId.AtomicQueryV3,
      loader,
      opts
    );

    const queryMetadata = queriesMetadata[0]; // only one query is supported

    checkCircuitOperator(circuitId, outs.operator);
    // validate selective disclosure
    if (queryMetadata.operator === Operators.SD) {
      try {
        await validateDisclosureNativeSDSupport(
          queryMetadata,
          outs,
          verifiablePresentation,
          loader
        );
      } catch (e) {
        throw new Error(`failed to validate selective disclosure: ${(e as Error).message}`);
      }
    } else if (!queryMetadata.fieldName && queryMetadata.operator == Operators.NOOP) {
      try {
        await validateEmptyCredentialSubjectNoopNativeSupport(outs);
      } catch (e: unknown) {
        throw new Error(`failed to validate operators: ${(e as Error).message}`);
      }
    } else {
      try {
        await validateOperators(queryMetadata, outs);
      } catch (e) {
        throw new Error(`failed to validate operators: ${(e as Error).message}`);
      }
    }

    // verify field inclusion / non-inclusion

    verifyFieldValueInclusionNativeExistsSupport(outs, queryMetadata);

    const { proofType, verifierID, nullifier, nullifierSessionID, linkID } = this.pubSignals;

    switch (query.proofType) {
      case ProofType.BJJSignature:
        if (proofType !== 1) {
          throw new Error('wrong proof type for BJJSignature');
        }
        break;
      case ProofType.Iden3SparseMerkleTreeProof:
        if (proofType !== 2) {
          throw new Error('wrong proof type for Iden3SparseMerkleTreeProof');
        }
        break;
      default:
      // if proof type is not specified in query any proof type in signals is OK.
    }

    const nSessionId = BigInt((params?.nullifierSessionId as string) ?? 0);
    if (nSessionId !== 0n) {
      if (BigInt(nullifier ?? 0) === 0n) {
        throw new Error('nullifier should be provided for nullification and should not be 0');
      }
      // verify nullifier information
      const verifierDIDParam = params?.verifierDid;
      if (!verifierDIDParam) {
        throw new Error('verifierDid is required');
      }

      const id = DID.idFromDID(verifierDIDParam as DID);

      if (verifierID.bigInt() != id.bigInt()) {
        throw new Error('wrong verifier is used for nullification');
      }

      if (nullifierSessionID !== nSessionId) {
        throw new Error(
          `wrong verifier session id is used for nullification, expected ${nSessionId}, got ${nullifierSessionID}`
        );
      }
    } else if (nullifierSessionID !== 0n) {
      throw new Error(`Nullifier id is generated but wasn't requested`);
    }

    if (!query.groupId && linkID !== 0n) {
      throw new Error(`proof contains link id, but group id is not provided`);
    }

    if (query.groupId && linkID === 0n) {
      throw new Error("proof doesn't contain link id, but group id is provided");
    }

    return this.pubSignals;
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.pubSignals.issuerID);
    if (!resolver) {
      throw new Error(`resolver not found for issuerID ${this.pubSignals.issuerID.string()}`);
    }

    await checkUserState(resolver, this.pubSignals.issuerID, this.pubSignals.issuerState);

    if (this.pubSignals.isRevocationChecked === 0) {
      return;
    }

    const issuerNonRevStateResolved = await checkIssuerNonRevState(
      resolver,
      this.pubSignals.issuerID,
      this.pubSignals.issuerClaimNonRevState
    );

    const acceptedStateTransitionDelay =
      opts?.acceptedStateTransitionDelay ?? defaultProofVerifyOpts;

    if (issuerNonRevStateResolved.latest) {
      return;
    }

    const timeDiff =
      Date.now() -
      getDateFromUnixTimestamp(Number(issuerNonRevStateResolved.transitionTimestamp)).getTime();
    if (timeDiff > acceptedStateTransitionDelay) {
      throw new Error('issuer state is outdated');
    }
  }
}
