import { ISchemaLoader, SchemaLoadResult } from '@lib/loaders/schema';
import nestedProperty from 'nested-property';
import { Id, SchemaHash } from '@iden3/js-iden3-core';
import { getContextPathKey } from '@lib/merklize/path';
import { TextDecoder } from 'util';
import { TextEncoder } from 'node:util';
import keccak256 from 'keccak256';

const operators: Map<string, number> = new Map([
  ['$noop', 0],
  ['$eq', 1],
  ['$lt', 2],
  ['$gt', 3],
  ['$in', 4],
  ['$nin', 5],
]);

const serializationIndexDataSlotAType = 'serialization:IndexDataSlotA';
const serializationIndexDataSlotBType = 'serialization:IndexDataSlotB';

const serializationValueDataSlotAType = 'serialization:ValueDataSlotA';
const serializationValueDataSlotBType = 'serialization:ValueDataSlotB';

// Query is a query to circuit
export interface Query {
  allowedIssuers: string;
  req: Map<string, unknown>;
  context: string;
  type: string;
  claimID?: string;
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
}

export async function checkQueryRequest(
  query: Query,
  outputs: ClaimOutputs,
  schemaLoader: ISchemaLoader,
): Promise<void> {
  if (
    query.allowedIssuers !== '*' &&
    query.allowedIssuers !== outputs.issuerId.string()
  ) {
    throw new Error('issuer is not in allowed list');
  }

  let loadResult: SchemaLoadResult;

  try {
    loadResult = await schemaLoader.load(query.context);
  } catch (e) {
    throw new Error(`can't load schema for request query`);
  }

  const schemaHash = CreateSchemaHash(query.context, query.type);
  if (schemaHash.toString() !== outputs.schemaHash.toString()) {
    throw new Error(`schema that was used is not equal to requested in query`);
  }

  const cq = await parseRequest(
    query.req,
    loadResult.schema,
    query.context,
    query.type,
    outputs.value.length,
    outputs.merklized,
  );

  if (query.req === undefined) {
    return;
  }

  if (outputs.operator !== cq.operator) {
    throw new Error(`operator that was used is not equal to request`);
  }
  if (outputs.operator === operators.get('$noop')) {
    // for noop operator slot and value are not used in this case
    return;
  }

  if (outputs.merklized === 1) {
    if (outputs.claimPathKey.toString() !== cq.claimPathKey.toString()) {
      throw new Error(`proof was generated for another path`);
    }
    if (outputs.claimPathNotExists === 1) {
      throw new Error(`proof doesn't contains target query key`);
    }
  } else {
    if (outputs.slotIndex.toString() !== cq.slotIndex.toString()) {
      throw new Error(`wrong claim slot was used in claim`);
    }
  }

  for (let index = 0; index < cq.values.length; index++) {
    if (outputs.value[index].toString(10) !== cq.values[index].toString(10)) {
      throw new Error(
        `comparison value that was used is not equal to requested in query`,
      );
    }
  }

  return;
}

async function parseRequest(
  req: Map<string, unknown>,
  schema: Uint8Array,
  credContext: string,
  credType: string,
  valueLength: number,
  merkalized: number,
): Promise<CircuitQuery> {
  if (!req) {
    return {
      operator: operators.get('$noop'),
      values: null,
      slotIndex: 0,
    };
  }

  let fieldName = '';
  let fieldReq: Map<string, unknown>;

  if (Object.keys(req).length > 1) {
    throw new Error(`multiple requests  not supported`);
  }

  for (const [key, value] of Object.entries(req)) {
    fieldName = key;

    fieldReq = value as Map<string, unknown>;

    if (Object.keys(fieldReq).length > 1) {
      throw new Error(`multiple predicates for one field not supported`);
    }
    break;
  }

  let operator: number;
  const values: bigint[] = new Array<bigint>(valueLength).fill(BigInt(0));
  for (const [key, value] of Object.entries(fieldReq)) {
    if (!operators.has(key)) {
      throw new Error(`operator is not supported by lib`);
    }
    operator = operators.get(key);

    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        values[index] = BigInt(value[index]);
      }
    } else {
      values[0] = BigInt(value as string);
    }
    break;
  }

  let slotIndex: number;
  let claimPathKey: bigint;
  if (merkalized == 1) {
    const txtSchema = new TextDecoder().decode(schema);
    const path = await getContextPathKey(txtSchema, credType, fieldName);
    path.prepend(['https://www.w3.org/2018/credentials#credentialSubject']);
    claimPathKey = await path.mtEntry();
  } else {
    slotIndex = getFieldSlotIndex(fieldName, credType, schema);
  }

  const cq: CircuitQuery = {
    claimPathKey,
    slotIndex,
    operator,
    values,
  };

  return cq;
}

function getFieldSlotIndex(
  fieldName: string,
  credentialType: string,
  schema: Uint8Array,
): number {
  const obj = JSON.parse(Buffer.from(schema).toString('utf-8'));
  const type = nestedProperty.get(
    obj,
    `@context.0.${credentialType}.@context.${fieldName}.@type`,
  );
  switch (type) {
    case serializationIndexDataSlotAType:
      return 2;
    case serializationIndexDataSlotBType:
      return 3;
    case serializationValueDataSlotAType:
      return 6;
    case serializationValueDataSlotBType:
      return 7;
    default:
      return -1;
  }
}

type CircuitQuery = {
  claimPathKey?: bigint;
  slotIndex?: number;
  values: bigint[];
  operator: number;
};

// TODO (illia-korotia): move to core like static method or contructor of SchemaHash type.
export function CreateSchemaHash(
  schemaContext: string,
  type: string,
): SchemaHash {
  const schemaID = new TextEncoder().encode(`${schemaContext}#${type}`);
  const bytes = new Uint8Array([...schemaID]);
  const h = keccak256(Buffer.from(bytes));
  return new SchemaHash(h.slice(-16));
}
