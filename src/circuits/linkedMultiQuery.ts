/* eslint-disable @typescript-eslint/no-unused-vars */
import { PubSignalsVerifier } from '@lib/circuits/registry';
import { Query } from '@lib/circuits/query';
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

/**
 * Verifies the linked multi-query circuit.
 * @beta
 */
export class LinkedMultiQueryVerifier implements PubSignalsVerifier {
  readonly pubSignals = new LinkedMultiQueryPubSignals();

  constructor(pubSignals: string[]) {
    this.pubSignals = this.pubSignals.pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(pubSignals)),
      10
    );
  }

  verifyIdOwnership(): Promise<void> {
    return Promise.resolve();
  }

  async verifyQuery(query: Query, schemaLoader?: DocumentLoader): Promise<BaseConfig> {
    let schema: JSONObject;
    const ldOpts = { documentLoader: schemaLoader ?? cacheLoader() };
    try {
      schema = (await ldOpts.documentLoader(query.context)).document as JSONObject;
    } catch (e) {
      throw new Error(`can't load schema for request query`);
    }
    const ldContextJSON = JSON.stringify(schema);
    const credentialSubject = query.credentialSubject as JSONObject;
    const schemaId: string = await Path.getTypeIDFromContext(ldContextJSON, query.type, ldOpts);
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
        queryMeta.merklizedSchema ? 0n : 1n,
        valueHash
      ]);
    });

    this.pubSignals.circuitQueryHash.sort(this.bigIntCompare);

    const zeros: Array<bigint> = Array.from({
      length: this.pubSignals.circuitQueryHash.length - queryHashes.length
    }).fill(BigInt(0)) as Array<bigint>;
    const fullQueryHashes: Array<bigint> = queryHashes.concat(zeros);
    fullQueryHashes.sort(this.bigIntCompare);

    if (!queryHashes.every((queryHash, i) => queryHash === this.pubSignals.circuitQueryHash[i])) {
      throw new Error('query hashes do not match');
    }

    return this.pubSignals as unknown as BaseConfig;
  }

  async verifyStates(): Promise<void> {
    return Promise.resolve();
  }

  bigIntCompare = (a: bigint, b: bigint): number => {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  };
}
