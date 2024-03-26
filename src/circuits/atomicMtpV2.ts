import { getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { Resolvers } from '@lib/state/resolver';
import { checkQueryV2Circuits, ClaimOutputs, Query } from '@lib/circuits/query';
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState, getResolverByID } from '@lib/circuits/common';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import {
  AtomicQueryMTPV2PubSignals,
  BaseConfig,
  byteEncoder,
  CircuitId
} from '@0xpolygonid/js-sdk';

const valuesSize = 64;
const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

export class AtomicQueryMTPV2PubSignalsVerifier
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  pubSignals = new AtomicQueryMTPV2PubSignals();
  constructor(pubSignals: string[]) {
    super();
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals))
    );

    if (!this.pubSignals.userID) {
      throw new Error('user id is not presented in proof public signals');
    }

    if (!this.pubSignals.requestID) {
      throw new Error('requestId is not presented in proof public signals');
    }

    this.userId = this.pubSignals.userID;
    this.challenge = this.pubSignals.requestID;
  }

  async verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts
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
      claimPathNotExists: this.pubSignals.claimPathNotExists,
      valueArraySize: valuesSize,
      isRevocationChecked: this.pubSignals.isRevocationChecked
    };
    await checkQueryV2Circuits(
      CircuitId.AtomicQueryMTPV2,
      query,
      outs,
      schemaLoader,
      opts,
      verifiablePresentation
    );

    return this.pubSignals;
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.pubSignals.issuerID);
    if (!resolver) {
      throw new Error(`resolver not found for issuerID ${this.pubSignals.issuerID.string()}`);
    }

    await checkUserState(resolver, this.pubSignals.issuerID, this.pubSignals.issuerClaimIdenState);

    if (this.pubSignals.isRevocationChecked === 0) {
      return;
    }

    const issuerNonRevStateResolved = await checkIssuerNonRevState(
      resolver,
      this.pubSignals.issuerID,
      this.pubSignals.issuerClaimNonRevState
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
