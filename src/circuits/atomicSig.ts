import { IStateResolver } from '@lib/state/resolver';
import { PubSignalsVerifier } from '@lib/circuits/registry';
import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { Core } from '@lib/core/core';
import { Id } from '@lib/core/id';
import { ISchemaLoader } from '@lib/loaders/schema';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkIssuerNonRevState, checkUserState } from '@lib/circuits/common';

export class AtomicQuerySigPubSignals
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  userState: bigint;
  claimSchema: bigint;
  issuerId: Id;
  issuerAuthState: bigint;
  issuerClaimNonRevState: bigint;
  slotIndex: number;
  values: bigint[];
  operator: number;
  timestamp: number;

  constructor(pubSignals: string[]) {
    super();
    if (pubSignals.length != 74) {
      throw new Error(
        `invalid number of Output values expected ${74} got ${
          pubSignals.length
        }`,
      );
    }

    this.issuerAuthState = BigInt(pubSignals[0]);
    const userIdBytes: Uint8Array = Core.intToBytes(BigInt(pubSignals[1]));
    this.userId = Id.idFromBytes(userIdBytes);
    this.userState = BigInt(pubSignals[2]);
    this.challenge = BigInt(pubSignals[3]);

    const issuerIdBytes: Uint8Array = Core.intToBytes(BigInt(pubSignals[4]));

    this.issuerId = Id.idFromBytes(issuerIdBytes);
    this.issuerClaimNonRevState = BigInt(pubSignals[5]);

    this.timestamp = parseInt(pubSignals[6], 10);

    this.claimSchema = BigInt(pubSignals[7]);

    this.slotIndex = parseInt(pubSignals[8], 10);
    this.operator = parseInt(pubSignals[9], 10);

    this.values = [];
    for (let index = 0; index < 64; index++) {
      const val = pubSignals[10 + index];
      this.values.push(BigInt(val));
    }
  }

  async verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void> {
    const outs: ClaimOutputs = {
      issuerId: this.issuerId.string(),
      schemaHash: this.claimSchema,
      operator: this.operator,
      slotIndex: this.slotIndex,
      value: this.values,
    };
    return await checkQueryRequest(query, outs, schemaLoader);
  }
  async verifyStates(resolver: IStateResolver): Promise<void> {
    await checkUserState(resolver, this.userId, this.userState);

    await resolver.resolve(this.issuerId.bigInt(), this.issuerAuthState);

    await checkIssuerNonRevState(
      resolver,
      this.issuerId,
      this.issuerClaimNonRevState,
    );
  }
}
