/* eslint-disable @typescript-eslint/no-unused-vars */
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { BaseConfig, LinkedMultiQueryPubSignals, byteEncoder } from '@0xpolygonid/js-sdk';

export class LinkedMultiQueryVerifier implements PubSignalsVerifier {
  pubSignals = new LinkedMultiQueryPubSignals();

  constructor(pubSignals: string[]) {
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals)),
      3
    );
  }

  verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    return Promise.resolve();
  }

  async verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts
  ): Promise<BaseConfig> {
    // compare query hash
    return this.pubSignals as unknown as BaseConfig;
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    return Promise.resolve();
  }
}
