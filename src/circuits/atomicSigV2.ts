import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { ISchemaLoader } from '@lib/loaders/schema';
import { Resolvers } from '@lib/state/resolver';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import {
  checkIssuerNonRevState,
  checkUserState,
  getResolverByID,
} from '@lib/circuits/common';
import { Hash, newHashFromString } from '@iden3/js-merkletree';
import { Id, SchemaHash, getDateFromUnixTimestamp } from '@iden3/js-iden3-core';

const valuesSize = 64;
const defaultProofVerifyOpts = 1 * 60 * 60 * 1000; // 1 hour

export class AtomicQuerySigV2PubSignals
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  issuerID?: Id;
  issuerAuthState?: Hash;
  issuerClaimNonRevState?: Hash;
  claimSchema: SchemaHash;
  slotIndex: number;
  operator: number;
  value: bigint[] = [];
  timestamp: number;
  merklized: number;
  claimPathKey?: bigint;
  claimPathNotExists: number;
  isRevocationChecked: number;

  constructor(pubSignals: string[]) {
    super();
    if (pubSignals.length != 13 + valuesSize) {
      throw new Error(
        `invalid number of Output values expected ${74} got ${
          pubSignals.length
        }`,
      );
    }

    let fieldIdx = 0;

    // -- merklized
    this.merklized = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    //  - userID
    this.userId = Id.fromBigInt(BigInt(pubSignals[fieldIdx]));
    fieldIdx++;

    // - issuerAuthState
    this.issuerAuthState = newHashFromString(pubSignals[fieldIdx]);
    fieldIdx++;

    // - requestID
    this.challenge = BigInt(pubSignals[fieldIdx]);
    fieldIdx++;

    // - issuerID
    this.issuerID = Id.fromBigInt(BigInt(pubSignals[fieldIdx]));
    fieldIdx++;

    this.isRevocationChecked = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    // - issuerClaimNonRevState
    this.issuerClaimNonRevState = newHashFromString(pubSignals[fieldIdx]);
    fieldIdx++;

    //  - timestamp
    this.timestamp = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    //  - claimSchema
    this.claimSchema = SchemaHash.newSchemaHashFromInt(
      BigInt(pubSignals[fieldIdx]),
    );
    fieldIdx++;

    // - ClaimPathNotExists
    this.claimPathNotExists = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    // - ClaimPathKey
    this.claimPathKey = BigInt(pubSignals[fieldIdx]);
    fieldIdx++;

    // - slotIndex
    this.slotIndex = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    // - operator
    this.operator = parseInt(pubSignals[fieldIdx]);
    fieldIdx++;

    //  - values
    for (let index = 0; index < valuesSize; index++) {
      this.value.push(BigInt(pubSignals[fieldIdx]));
      fieldIdx++;
    }
  }

  async verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void> {
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
      isRevocationChecked: this.isRevocationChecked,
    };
    return await checkQueryRequest(query, outs, schemaLoader);
  }
  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.issuerID);
    if (!resolver) {
      throw new Error(`resolver not found for issuerID ${this.issuerID}`);
    }

    await checkUserState(resolver, this.issuerID, this.issuerAuthState);

    if (this.isRevocationChecked === 0) {
      return;
    }

    const issuerNonRevStateResolved = await checkIssuerNonRevState(
      resolver,
      this.issuerID,
      this.issuerClaimNonRevState,
    );

    let acceptedStateTransitionDelay = defaultProofVerifyOpts;
    if (opts?.acceptedStateTransitionDelay) {
      acceptedStateTransitionDelay = opts.acceptedStateTransitionDelay;
    }

    if (!issuerNonRevStateResolved.latest) {
      const timeDiff =
        Date.now() -
        getDateFromUnixTimestamp(
          Number(issuerNonRevStateResolved.transitionTimestamp),
        ).getMilliseconds();
      if (timeDiff > acceptedStateTransitionDelay) {
        throw new Error('issuer state is outdated');
      }
    }
  }
}
