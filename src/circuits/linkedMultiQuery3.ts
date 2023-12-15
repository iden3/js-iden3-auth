/* eslint-disable @typescript-eslint/no-unused-vars */
import { PubSignalsVerifier, VerifyOpts } from '@lib/circuits/registry';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader, Path } from '@iden3/js-jsonld-merklization';
import {
  BaseConfig,
  JSONObject,
  LinkedMultiQueryPubSignals,
  byteEncoder,
  cacheLoader,
  createSchemaHash,
  parseQueriesMetadata
} from '@0xpolygonid/js-sdk';
import { poseidon } from '@iden3/js-crypto';
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
    let schema: JSONObject;
    const ldOpts = { documentLoader: schemaLoader ?? cacheLoader() };
    try {
      const loader = schemaLoader ?? cacheLoader();
      schema = (await ldOpts.documentLoader(query.context)).document as JSONObject;
    } catch (e) {
      throw new Error(`can't load schema for request query`);
    }
    const ldContextJSON = JSON.stringify(schema);
    const credentialSubject = query.credentialSubject as JSONObject;
    const schemaId: string = await Path.getTypeIDFromContext(
      JSON.stringify(schema),
      query.type,
      ldOpts
    );
    const schemaHash = createSchemaHash(byteEncoder.encode(schemaId));

    const queriesMetadata = await parseQueriesMetadata(
      query.type,
      ldContextJSON,
      credentialSubject,
      ldOpts
    );

    const queryHashes = queriesMetadata.map((queryMeta) => {
      const valueHash = poseidon.spongeHashX(queryMeta.values, 6);
      return poseidon.hash([
        schemaHash.bigInt(),
        BigInt(queryMeta.slotIndex),
        BigInt(queryMeta.operator),
        BigInt(queryMeta.claimPathKey),
        // TODO: claimAPathNotExists
        BigInt(0),
        valueHash
      ]);
    });

    if (!queryHashes.every((queryHash, i) => queryHash === this.pubSignals.circuitQueryHash[i])) {
      throw new Error('query hashes do not match');
    }

    return this.pubSignals as unknown as BaseConfig;
  }

  async verifyStates(resolvers: Resolvers, opts?: VerifyOpts): Promise<void> {
    return Promise.resolve();
  }
}
