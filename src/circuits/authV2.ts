import { Id } from '@iden3/js-iden3-core';
import { Query } from '@lib/circuits/query';
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkGlobalState, getResolverByID } from '@lib/circuits/common';
import { Hash, newHashFromString } from '@iden3/js-merkletree';
import { Resolvers } from '@lib/state/resolver';

const defaultAuthVerifyOpts = 5 * 60 * 1000; // 5 minutes
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

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.userId);
    if (resolver === undefined) {
      throw new Error(`resolver not found for id ${this.userId.string()}`);
    }
    const gist = await checkGlobalState(resolver, this.gistRoot);

    let acceptedStateTransitionDelay = defaultAuthVerifyOpts;
    if (!!opts && !!opts.AcceptedStateTransitionDelay) {
      acceptedStateTransitionDelay = Number(opts.AcceptedStateTransitionDelay);
    }

    if (!gist.latest) {
      const timeDiff = Date.now() - Number(gist.transitionTimestamp);
      if (timeDiff > acceptedStateTransitionDelay) {
        throw new Error('global state is outdated');
      }
    }
  }

  verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    return super.verifyIdOwnership(sender, challenge);
  }
}
