import { IStateResolver, ResolvedState } from 'state/resolver';
import { PubSignalsVerifier } from './registry';
import { checkQueryRequest, ClaimOutputs, Query } from './query';
import { Core } from '../core/core';
import { Id } from '../core/id';
import { ISchemaLoader } from 'loaders/schema';

export class AtomicQuerySigPubSignals implements PubSignalsVerifier {
  userId: Id;
  userState: bigint;
  challenge: bigint;
  claimSchema: bigint;
  issuerId: Id;
  issuerState: bigint;
  issuerAuthState: bigint;
  issuerClaimNonRevState: bigint;
  slotIndex: number;
  values: bigint[];
  operator: number;
  timestamp: number;

  constructor(pubSignals: string[]) {
    if (pubSignals.length != 75) {
      throw new Error(
        `invalid number of Output values expected ${75} got ${
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
    this.issuerState = BigInt(pubSignals[5]);
    this.issuerClaimNonRevState = BigInt(pubSignals[6]);

    this.timestamp = parseInt(pubSignals[7], 10);

    this.claimSchema = BigInt(pubSignals[8]);

    this.slotIndex = parseInt(pubSignals[9], 10);
    this.operator = parseInt(pubSignals[10], 10);

    this.values = [];
    for (let index = 0; index < 64; index++) {
      const val = pubSignals[11 + index];
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
    const userStateResolved: ResolvedState = await resolver.resolve(
      this.userId.bigInt(),
      this.userState,
    );
    if (!userStateResolved.latest) {
      throw new Error(`only latest states are supported`);
    }

    const issuerStateResolved: ResolvedState = await resolver.resolve(
      this.issuerId.bigInt(),
      this.issuerState,
    );
    if (!issuerStateResolved) {
      throw new Error(`issuer state is not valid`);
    }
    return;
  }
  async verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    if (sender !== this.userId.string()) {
      throw new Error(
        `sender is not used for proof creation, expected ${sender}, user from public signals: ${this.userId.string()}  `,
      );
    }
    if (challenge.toString() !== this.challenge.toString()) {
      throw new Error(
        `challenge is not used for proof creation, expected ${challenge}, challenge from public signals: ${this.challenge.toString()}  `,
      );
    }
  }
}
