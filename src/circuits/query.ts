import keccak256 from 'keccak256';
import { ISchemaLoader, SchemaLoadResult } from '@lib/loaders/schema';
import nestedProperty from 'nested-property';
import { Schema } from '@lib/protocol/models';
import { fromLittleEndian } from '@lib/core/util';

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
  allowedIssuers: string[];
  req: Map<string, unknown>;
  schema: Schema;
  claimId: string;
}

// ClaimOutputs fields that are used in proof generation
export interface ClaimOutputs {
  issuerId: string;
  schemaHash: bigint;
  slotIndex: number;
  operator: number;
  value: bigint[];
}

export async function checkQueryRequest(
  query: Query,
  outputs: ClaimOutputs,
  schemaLoader: ISchemaLoader,
): Promise<void> {
  const issuerAllowed = query.allowedIssuers.some(
    (issuer) => issuer === '*' || issuer === outputs.issuerId,
  );
  if (!issuerAllowed) {
    throw new Error('issuer is not in allowed list');
  }

  let loadResult: SchemaLoadResult;

  try {
    loadResult = await schemaLoader.load(query.schema);
  } catch (e) {
    throw new Error(`can't load schema for request query`);
  }

  if (loadResult.extension !== 'json-ld') {
    throw new Error('only json-ld schema is supported');
  }
  const toHash = new Uint8Array([
    ...loadResult.schema,
    ...toBytes(query.schema.type),
  ]);

  const schemaHash = keccak256(Buffer.from(toHash));

  // only json ld-schema are supported
  const cq = parseRequest(
    query.req,
    loadResult.schema,
    query.schema.type,
    outputs.value.length,
  );

  if (outputs.operator !== cq.operator) {
    throw new Error(`operator that was used is not equal to request`);
  }
  if (outputs.operator === operators.get('$noop')) {
    // for noop operator slot and value are not used in this case
    return;
  }

  if (outputs.slotIndex !== cq.slotIndex) {
    throw new Error(`wrong claim slot was used in claim`);
  }

  if (outputs.operator !== cq.operator) {
    throw new Error(
      `operator that was used is not equal to requested in query`,
    );
  }
  for (let index = 0; index < cq.values.length; index++) {
    if (outputs.value[index].toString(10) !== cq.values[index].toString(10)) {
      throw new Error(
        `comparison value that was used is not equal to requested in query`,
      );
    }
  }

  const shBigInt: bigint = fromLittleEndian(
    schemaHash.slice(Math.ceil(schemaHash.length / 2), schemaHash.length),
  );

  if (shBigInt.toString() !== outputs.schemaHash.toString()) {
    throw new Error(`schema that was used is not equal to requested in query`);
  }
  return;
}

const toBytes = (s: string): Uint8Array => {
  //TODO: buffer is not present in browser
  const buffer = Buffer.from(s, 'utf8');
  const result = Uint8Array.from(buffer);

  return result;
};

function parseRequest(
  req: Map<string, unknown>,
  schema: Uint8Array,
  credType: string,
  valueLength: number,
): CircuitQuery {
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

  const slotIndex = getFieldSlotIndex(fieldName, credType, schema);

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

  const cq: CircuitQuery = {
    operator,
    values,
    slotIndex,
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
  slotIndex: number;
  values: bigint[];
  operator: number;
};
