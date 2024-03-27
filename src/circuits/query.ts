import { Id, SchemaHash } from '@iden3/js-iden3-core';
import { getDocumentLoader } from '@iden3/js-jsonld-merklization';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import {
  Operators,
  CircuitId,
  ProofQuery,
  parseQueriesMetadata,
  JSONObject,
  checkQueryRequest,
  validateDisclosureV2Circuit,
  validateEmptyCredentialSubjectV2Circuit,
  verifyFieldValueInclusionV2,
  validateOperators,
  checkCircuitOperator
} from '@0xpolygonid/js-sdk';
import { VerifyOpts } from './registry';
import { JsonLd } from 'jsonld/jsonld-spec';

export const userStateError = new Error(`user state is not valid`);

// Query is a query to circuit
export interface Query {
  allowedIssuers: string[];
  credentialSubject: { [key: string]: unknown };
  context: string;
  type: string;
  claimID?: string;
  skipClaimRevocationCheck?: boolean;
  proofType?: string;
  groupId?: number;
}

// ClaimOutputs fields that are used in proof generation
export interface ClaimOutputs {
  issuerId: Id;
  schemaHash: SchemaHash;
  slotIndex?: number;
  operator: number;
  value: bigint[];
  timestamp: number;
  merklized: number;
  claimPathKey?: bigint;
  claimPathNotExists?: number;
  valueArraySize: number;
  isRevocationChecked: number;
  operatorOutput?: bigint;
}

export async function checkQueryV2Circuits(
  circuitId: CircuitId.AtomicQueryMTPV2 | CircuitId.AtomicQuerySigV2,
  query: ProofQuery,
  outs: ClaimOutputs,
  schemaLoader: DocumentLoader | undefined,
  opts: VerifyOpts | undefined,
  verifiablePresentation: JSON | undefined
) {
  if (!query.type) {
    throw new Error(`proof query type is undefined`);
  }

  const loader = schemaLoader || getDocumentLoader();

  // validate schema
  let context: JsonLd;
  try {
    context = (await loader(query.context ?? '')).document;
  } catch (e) {
    throw new Error(`can't load schema for request query`);
  }

  const queriesMetadata = await parseQueriesMetadata(
    query.type,
    JSON.stringify(context),
    query.credentialSubject as JSONObject,
    {
      documentLoader: loader
    }
  );

  await checkQueryRequest(query, queriesMetadata, context, outs, circuitId, loader, opts);

  const queryMetadata = queriesMetadata[0]; // only one query is supported

  checkCircuitOperator(circuitId, outs.operator);

  // validate selective disclosure
  if (queryMetadata.operator === Operators.SD) {
    try {
      await validateDisclosureV2Circuit(queryMetadata, outs, verifiablePresentation, loader);
    } catch (e) {
      throw new Error(`failed to validate selective disclosure: ${(e as Error).message}`);
    }
  } else if (!queryMetadata.fieldName && queryMetadata.operator == Operators.NOOP) {
    try {
      await validateEmptyCredentialSubjectV2Circuit(queryMetadata, outs);
    } catch (e: unknown) {
      throw new Error(`failed to validate operators: ${(e as Error).message}`);
    }
  } else {
    try {
      await validateOperators(queryMetadata, outs);
    } catch (e) {
      throw new Error(`failed to validate operators: ${(e as Error).message}`);
    }
  }

  // verify field inclusion
  verifyFieldValueInclusionV2(outs, queryMetadata);
}
