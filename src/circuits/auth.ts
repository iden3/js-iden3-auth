import { Core } from '../core/core';
import { Id } from '../core/id';
import { IStateResolver, ResolvedState } from 'state/resolver';
import { Query } from './query';
import { PubSignalsVerifier } from './registry';
import { IDOwnershipPubSignals } from './ownershipVerifier';

export class AuthPubSignals
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  userState: bigint;

  constructor(pubSignals: string[]) {
    super();
    if (pubSignals.length != 3) {
      throw new Error(
        `invalid number of Output values expected ${3} got ${
          pubSignals.length
        }`,
      );
    }
    this.challenge = BigInt(pubSignals[0]);
    this.userState = BigInt(pubSignals[1]);

    const bytes: Uint8Array = Core.intToBytes(BigInt(pubSignals[2]));
    this.userId = Id.idFromBytes(bytes);
  }
  async verifyQuery(_query: Query): Promise<void> {
    throw new Error('Method not implemented.');
  }

  async verifyStates(resolver: IStateResolver): Promise<void> {
    const userStateResolved: ResolvedState = await resolver.resolve(
      this.userId.bigInt(),
      this.userState,
    );
    if (!userStateResolved.latest) {
      throw new Error(`only latest states are supported`);
    }
    return;
  }
}
