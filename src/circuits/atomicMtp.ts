import { Core } from 'core/core';
import { Id } from 'core/id';
import { ISchemaLoader } from 'loaders/schema';
import { IStateResolver, ResolvedState } from 'state/resolver';
import { checkQueryRequest, ClaimOutputs, Query } from './query';
import { PubSignalsUnmarshaller, PubSignalsVerifier } from './registry';

export class AtomicQueryMTPPubSignals
  implements PubSignalsVerifier, PubSignalsUnmarshaller
{
  userId: Id;
  userState: bigint;
  challenge: bigint;
  claimSchema: bigint;
  issuerClaimIdenState: bigint;
  issuerId: Id;
  slotIndex: number;
  values: bigint[];
  operator: number;
  timestamp: number;

  unmarshall(pubsignals: string[]): Promise<void> {
    if (pubsignals.length != 73) {
      throw new Error(
        `invalid number of Output values expected ${73} got ${
          pubsignals.length
        }`,
      );
    }

    const userIdBytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[0]));
    this.userId = Id.idFromBytes(userIdBytes);
    this.userState = BigInt(pubsignals[1]);
    this.challenge = BigInt(pubsignals[2]);
    this.issuerClaimIdenState = BigInt(pubsignals[3]);
    const issuerIdBytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[4]));

    this.issuerId = Id.idFromBytes(issuerIdBytes);
    this.timestamp = parseInt(pubsignals[5], 10);

    this.claimSchema = BigInt(pubsignals[6]);

    this.slotIndex = parseInt(pubsignals[7], 10);
    this.operator = parseInt(pubsignals[8], 10);

    this.values = [];
    for (let index = 0; index < 64; index++) {
      const val = pubsignals[9 + index];
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
      this.issuerClaimIdenState,
    );
    if (!issuerStateResolved) {
      throw new Error(`issuer state is not valid`);
    }
    return;
  }
}
