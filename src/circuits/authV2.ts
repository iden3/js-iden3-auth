import { getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { Query } from '@lib/circuits/query';
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkGlobalState, getResolverByID } from '@lib/circuits/common';
import { Resolvers } from '@lib/state/resolver';
import { Mixin } from 'ts-mixer';
import { AuthV2PubSignals, byteEncoder } from '@0xpolygonid/js-sdk';

const defaultAuthVerifyOpts = 5 * 60 * 1000; // 5 minutes
export class AuthPubSignalsV2
  extends Mixin(IDOwnershipPubSignals, AuthV2PubSignals)
  implements PubSignalsVerifier
{
  constructor(pubSignals: string[]) {
    super();
    this.pubSignalsUnmarshal(byteEncoder.encode(JSON.stringify(pubSignals)));

    this.userId = this.userID;
    this.challenge;
  }

  async verifyQuery(_query: Query): Promise<void> {
    throw new Error(`auth circuit doesn't support queries`);
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.userId);
    if (!resolver) {
      throw new Error(`resolver not found for id ${this.userId.string()}`);
    }
    const gist = await checkGlobalState(resolver, this.GISTRoot);

    let acceptedStateTransitionDelay = defaultAuthVerifyOpts;
    if (opts?.acceptedStateTransitionDelay) {
      acceptedStateTransitionDelay = opts.acceptedStateTransitionDelay;
    }

    if (!gist.latest) {
      const timeDiff =
        Date.now() - getDateFromUnixTimestamp(Number(gist.transitionTimestamp)).getTime();
      if (timeDiff > acceptedStateTransitionDelay) {
        throw new Error('global state is outdated');
      }
    }
  }

  verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    return super.verifyIdOwnership(sender, challenge);
  }
}
