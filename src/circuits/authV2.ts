import { Id } from '@iden3/js-iden3-core';
import { IStateResolver } from '@lib/state/resolver';
import { Query } from '@lib/circuits/query';
import { PubSignalsVerifier } from '@lib/circuits/registry';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkGlobalState } from '@lib/circuits/common';
import { Hash, newHashFromString } from '@iden3/js-merkletree';

export class AuthPubSignalsV2
  extends IDOwnershipPubSignals
  implements PubSignalsVerifier
{
  gistRoot: Hash;

  constructor(pubSignals: string[]) {
    super();
    if (pubSignals.length != 3) {
      throw new Error(
        `invalid number of Output values expected ${3} got ${
          pubSignals.length
        }`,
      );
    }

    this.userId = Id.fromBigInt(BigInt(pubSignals[0]));
    this.challenge = BigInt(pubSignals[1]);
    this.gistRoot = newHashFromString(pubSignals[2]);
  }

  async verifyQuery(_query: Query): Promise<void> {
    throw new Error(`auth circuit doesn't support queries`);
  }

  async verifyStates(resolver: IStateResolver): Promise<void> {
    await checkGlobalState(resolver, this.gistRoot);
  }

  verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    return super.verifyIdOwnership(sender, challenge);
  }
}
