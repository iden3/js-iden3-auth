import { getDateFromUnixTimestamp } from '@iden3/js-iden3-core';
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { IDOwnershipPubSignals } from '@lib/circuits/ownershipVerifier';
import { checkGlobalState, getResolverByID } from '@lib/circuits/common';
import { Resolvers } from '@lib/state/resolver';
import { AuthV2PubSignals, BaseConfig, byteEncoder } from '@0xpolygonid/js-sdk';

const defaultAuthVerifyOpts = 5 * 60 * 1000; // 5 minutes
export class AuthPubSignalsV2 extends IDOwnershipPubSignals implements PubSignalsVerifier {
  pubSignals = new AuthV2PubSignals();
  constructor(pubSignals: string[]) {
    super();
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals))
    );

    this.userId = this.pubSignals.userID;
    this.challenge = this.pubSignals.challenge;
  }

  verifyQuery(): Promise<BaseConfig> {
    throw new Error(`authV2 circuit doesn't support queries`);
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    const resolver = getResolverByID(resolvers, this.userId);
    if (!resolver) {
      throw new Error(`resolver not found for id ${this.userId.string()}`);
    }
    const gist = await checkGlobalState(resolver, this.pubSignals.GISTRoot);

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
