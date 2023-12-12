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

    // const valueHash = [];
    // for (let i = 0; i < 3; i++) {
    //   valueHash[i] = poseidon.spongeHashX(valueArraySize, 6); // 6 - max size of poseidon hash available on-chain
    // }

    /////////////////////////////////////////////////////////////////
    // Calculate query hash
    /////////////////////////////////////////////////////////////////
    // 4950 constraints (SpongeHash+Poseidon)

    // circuitQueryHash[i] <== Poseidon(6)([
    //     claimSchema,
    //     slotIndex[i],
    //     operator[i],
    //     claimPathKey[i],
    //     claimPathNotExists[i],
    //     valueHash[i]
    // ]);

    return this.pubSignals as unknown as BaseConfig;
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    return Promise.resolve();
  }
}
