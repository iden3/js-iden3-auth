import { Core } from 'core/core';
import { Id } from 'core/id';
import { IStateResolver, ResolvedState } from 'state/resolver';
import { Query } from './query';
import { PubSignalsUnmarshaller, PubSignalsVerifier } from './registry';

export class AuthPubSignals
  implements PubSignalsVerifier, PubSignalsUnmarshaller
{
  challenge: bigint;
  userState: bigint;
  userId: Id;

  unmarshall(pubsignals: string[]): Promise<void> {
    if (pubsignals.length != 3) {
      throw new Error(
        `invalid number of Output values expected ${3} got ${
          pubsignals.length
        }`,
      );
    }
    this.challenge = BigInt(pubsignals[0]);
    this.userState = BigInt(pubsignals[1]);

    const bytes: Uint8Array = Core.intToBytes(BigInt(pubsignals[2]));
    this.userId = Id.idFromBytes(bytes);
    return;
  }
  async verifyQuery(query: Query): Promise<void> {
    throw new Error('Method not implemented.');
  }
  async verifyStates(resolver: IStateResolver): Promise<void> {
    let userStateResolved: ResolvedState = await resolver.resolve(
      this.userId.bigInt(),
      this.userState,
    );
    if (!userStateResolved.latest) {
      throw new Error(`only latest states are supported`);
    }
    return;
  }
}
