import { IStateResolver, ResolvedState } from 'state/resolver';
import { PubSignalsUnmarshaller, PubSignalsVerifier } from './registry';
import { checkQueryRequest, ClaimOutputs, Query } from './query';
import { Core } from 'core/core';
import { Id } from 'core/id';
import { ISchemaLoader } from 'loaders/schema';

export class AtomicQuerySigPubSignals
  implements PubSignalsVerifier, PubSignalsUnmarshaller
{
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

  unmarshall(pubsignals: string[]): Promise<void> {
    if (pubsignals.length != 75) {
      throw new Error(
        `invalid number of Output values expected ${75} got ${
          pubsignals.length
        }`,
      );
    }

    this.issuerAuthState = BigInt(pubsignals[0]);
    const userIdBytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[1]));
    this.userId = Id.idFromBytes(userIdBytes);
    this.userState = BigInt(pubsignals[2]);
    this.challenge = BigInt(pubsignals[3]);

    const issuerIdBytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[4]));

    this.issuerId = Id.idFromBytes(issuerIdBytes);
    this.issuerState = BigInt(pubsignals[5]);
    this.issuerClaimNonRevState = BigInt(pubsignals[6]);

    this.timestamp = parseInt(pubsignals[7], 10);

    this.claimSchema = BigInt(pubsignals[8]);

    this.slotIndex = parseInt(pubsignals[9], 10);
    this.operator = parseInt(pubsignals[10], 10);

    this.values = [];
    for (let index = 0; index < 64; index++) {
      const val = pubsignals[11 + index];
      this.values.push(this.values[val]);
    }

    return;
  }
  async verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void> {
    let outs: ClaimOutputs = {
      issuerId: this.issuerId.string(),
      schemaHash: this.claimSchema,
      operator: this.operator,
      slotIndex: this.slotIndex,
      value: this.values,
    };
    return await checkQueryRequest(query, outs, schemaLoader);
  }
  async verifyStates(resolver: IStateResolver): Promise<void> {
    let userStateResolved: ResolvedState = await resolver.resolve(
      this.userId.bigInt(),
      this.userState,
    );
    if (!userStateResolved.latest) {
      throw new Error(`only latest states are supported`);
    }

    let issuerStateResolved: ResolvedState = await resolver.resolve(
      this.issuerId.bigInt(),
      this.issuerState,
    );
    if (!issuerStateResolved) {
      throw new Error(`issuer state is not valid`);
    }
    return;
  }
}
