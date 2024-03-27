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
  parseQueriesMetadata,
  calculateQueryHashV3,
  calculateCoreSchemaHash,
  QueryMetadata,
  LinkedMultiQueryInputs,
  Operators,
  fieldValueFromVerifiablePresentation
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
      byteEncoder.encode(JSON.stringify(pubSignals))
    );
  }

  verifyIdOwnership(): Promise<void> {
    return Promise.resolve();
  }

  async verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON
  ): Promise<BaseConfig> {
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
    const schemaHash = calculateCoreSchemaHash(byteEncoder.encode(schemaId));

    const queriesMetadata = await parseQueriesMetadata(
      query.type,
      ldContextJSON,
      credentialSubject,
      ldOpts
    );

    const request: { queryHash: bigint; queryMeta: QueryMetadata }[] = [];
    const merklized = queriesMetadata[0]?.merklizedSchema ? 1 : 0;
    for (let i = 0; i < LinkedMultiQueryInputs.queryCount; i++) {
      const queryMeta = queriesMetadata[i];
      const values = queryMeta?.values ?? [];
      const valArrSize = values.length;

      const queryHash = calculateQueryHashV3(
        values,
        schemaHash,
        queryMeta?.slotIndex ?? 0,
        queryMeta?.operator ?? 0,
        queryMeta?.claimPathKey.toString() ?? 0,
        valArrSize,
        merklized,
        0,
        0,
        0
      );
      request.push({ queryHash, queryMeta });
    }

    const queryHashCompare = (a: { queryHash: bigint }, b: { queryHash: bigint }): number => {
      if (a.queryHash < b.queryHash) return -1;
      if (a.queryHash > b.queryHash) return 1;
      return 0;
    };

    const pubSignalsMeta = this.pubSignals.circuitQueryHash.map((queryHash, index) => ({
      queryHash,
      operatorOutput: this.pubSignals.operatorOutput[index]
    }));

    pubSignalsMeta.sort(queryHashCompare);
    request.sort(queryHashCompare);

    for (let i = 0; i < LinkedMultiQueryInputs.queryCount; i++) {
      if (request[i].queryHash != pubSignalsMeta[i].queryHash) {
        throw new Error('query hashes do not match');
      }

      if (request[i].queryMeta?.operator === Operators.SD) {
        const disclosedValue = await fieldValueFromVerifiablePresentation(
          request[i].queryMeta.fieldName,
          verifiablePresentation,
          schemaLoader
        );
        if (disclosedValue != pubSignalsMeta[i].operatorOutput) {
          throw new Error('disclosed value is not in the proof outputs');
        }
      }
    }

    return this.pubSignals as unknown as BaseConfig;
  }

  async verifyStates(): Promise<void> {
    return Promise.resolve();
  }

  private bigIntCompare = (a: bigint, b: bigint): number => {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  };
}
