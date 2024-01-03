import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState, getResolverByID } from '@lib/circuits/common';
import { DID, getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { AtomicQueryV3PubSignals, byteEncoder, JSONObject, ProofType } from '@0xpolygonid/js-sdk';

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
    opts?: VerifyOpts,
    params?: JSONObject
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

    const { proofType, verifierID, nullifier, nullifierSessionID } = this.pubSignals;

    const isValidSigType = query.proofType === ProofType.BJJSignature && proofType === 1;
    const isValidMTPType =
      query.proofType === ProofType.Iden3SparseMerkleTreeProof && proofType === 2;

    if (!isValidSigType && !isValidMTPType) {
      throw new Error('invalid proof type');
    }
    const nullifierSessionIDparam = params?.nullifierSessionId;

    if (nullifierSessionIDparam) {
      if (nullifier && BigInt(nullifier) !== 0n) {
        // verify nullifier information
        const verifierDIDParam = params?.verifierDid;
        if (!verifierDIDParam) {
          throw new Error('verifierDid is required');
        }

        const id = DID.idFromDID(verifierDIDParam as DID);

        if (verifierID.bigInt() != id.bigInt()) {
          throw new Error('wrong verifier is used for nullification');
        }
        const nSessionId = BigInt(nullifierSessionIDparam as string);

        if (nullifierSessionID !== nSessionId) {
          throw new Error(
            `wrong verifier session id is used for nullification, expected ${nSessionId}, got ${nullifierSessionID}`
          );
        }
      }
    } else if (nullifierSessionID !== 0n) {
      throw new Error(`Nullifier id is generated but wasn't requested`);
    }

    if (typeof query.groupId === 'undefined' && this.pubSignals.linkID !== 0n) {
      throw new Error(`proof contains link id, but group id is not provided`);
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
