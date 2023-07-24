import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState, getResolverByID } from '@lib/circuits/common';
import { getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { Mixin } from 'ts-mixer';
import { AtomicQuerySigV2PubSignals, byteEncoder } from '@0xpolygonid/js-sdk';

const valuesSize = 64;
const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

export class AuthAtomicQuerySigV2PubSignals
  extends Mixin(IDOwnershipPubSignals, AtomicQuerySigV2PubSignals)
  implements PubSignalsVerifier
{
  constructor(pubSignals: string[]) {
    super();
    this.pubSignalsUnmarshal(byteEncoder.encode(JSON.stringify(pubSignals)));

    this.userId = this.userID;
    this.challenge = this.requestID;
  }

  async verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts
  ): Promise<void> {
    const outs: ClaimOutputs = {
      issuerId: this.issuerID,
      schemaHash: this.claimSchema,
      slotIndex: this.slotIndex,
      operator: this.operator,
      value: this.value,
      timestamp: this.timestamp,
      merklized: this.merklized,
      claimPathKey: this.claimPathKey,
      claimPathNotExists: this.claimPathNotExists,
      valueArraySize: valuesSize,
      isRevocationChecked: this.isRevocationChecked
    };
    return await checkQueryRequest(query, outs, schemaLoader, verifiablePresentation, opts);
  }
  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.issuerID);
    if (!resolver) {
      throw new Error(`resolver not found for issuerID ${this.issuerID.string()}`);
    }

    await checkUserState(resolver, this.issuerID, this.issuerAuthState);

    if (this.isRevocationChecked === 0) {
      return;
    }

    const issuerNonRevStateResolved = await checkIssuerNonRevState(
      resolver,
      this.issuerID,
      this.issuerClaimNonRevState
    );

    let acceptedStateTransitionDelay = defaultProofVerifyOpts;
    if (opts?.acceptedStateTransitionDelay) {
      acceptedStateTransitionDelay = opts.acceptedStateTransitionDelay;
    }

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
