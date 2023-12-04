import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState, getResolverByID } from '@lib/circuits/common';
import { DID, getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { AtomicQueryV3PubSignals, byteEncoder, ProofType } from '@0xpolygonid/js-sdk';

const valuesSize = 64;
const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

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
    opts?: VerifyOpts
  ): Promise<void> {
    const outs: ClaimOutputs = {
      issuerId: this.pubSignals.issuerID,
      schemaHash: this.pubSignals.claimSchema,
      slotIndex: this.pubSignals.slotIndex,
      operator: this.pubSignals.operator,
      value: this.pubSignals.value,
      timestamp: this.pubSignals.timestamp,
      merklized: this.pubSignals.merklized,
      claimPathKey: this.pubSignals.claimPathKey,
      claimPathNotExists: this.pubSignals.claimPathNotExists,
      valueArraySize: valuesSize,
      isRevocationChecked: this.pubSignals.isRevocationChecked
    };
    await checkQueryRequest(query, outs, schemaLoader, verifiablePresentation, opts);

    const { proofType, verifierID, verifierSessionID, linkID, nullifier } = this.pubSignals;

    if (
      !(query.proofType === ProofType.BJJSignature && proofType === 1) &&
      !(query.proofType === ProofType.Iden3SparseMerkleTreeProof && proofType === 2)
    ) {
      throw new Error('invalid proof type');
    }

    if (nullifier && BigInt(nullifier) !== 0n) {
      // verify nullifier information
      if (!opts?.verifierDID) {
        throw new Error('verifierDID is required');
      }

      const id = DID.idFromDID(opts.verifierDID);

      if (verifierID.bigInt() != id.bigInt()) {
        throw new Error('wrong verifier is used for nullification');
      }

      if (!query.verifierSessionId) {
        throw new Error('verifierSessionId is required');
      }

      const vSessionID = BigInt(query.verifierSessionId);

      if (verifierSessionID !== vSessionID) {
        throw new Error(
          `wrong verifier session id is used for nullification, expected ${vSessionID}, got ${verifierSessionID}`
        );
      }
    }

    if (query.linkSessionId && !linkID) {
      throw new Error("proof doesn't contain link id, but link session id is provided");
    }
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

    // if IsRevocationChecked is set to 0. Skip validation revocation status of issuer.
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

    if (!issuerNonRevStateResolved.latest) {
      const timeDiff =
        Date.now() -
        getDateFromUnixTimestamp(Number(issuerNonRevStateResolved.transitionTimestamp)).getTime();
      if (timeDiff > acceptedStateTransitionDelay) {
        throw new Error('issuer state is outdated');
      }
    }
  }
}
