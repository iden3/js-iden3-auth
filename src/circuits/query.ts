import { Core } from '../core/core';
import keccak256 from 'keccak256';
import { ISchemaLoader } from 'loaders/schema';
import nestedProperty from 'nested-property';
import { Schema } from 'protocol/models';

const operators: Map<string, number> = new Map([
  ['$eq', 0],
  ['$lt', 1],
  ['$gt', 2],
  ['$in', 3],
  ['$nin', 4],
]);

const serializationIndexType = 'serialization:Index';
const serializationIndexDataSlotAType = 'serialization:IndexDataSlotA';
const serializationIndexDataSlotBType = 'serialization:IndexDataSlotB';

const serializationValueType = 'serialization:Value';
const serializationValueDataSlotAType = 'serialization:ValueDataSlotA';
const serializationValueDataSlotBType = 'serialization:ValueDataSlotB';

// Query is a query to circuit
export interface Query {
  AllowedIssuers: string[];
  Req: Map<string, unknown>;
  Schema: Schema;
  ClaimId: string;
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
  const issuerAllowed = query.AllowedIssuers.some(
    (issuer) => issuer === '*' || issuer === outputs.issuerId,
  );

  const loadResult = await schemaLoader.load(query.Schema);

  if (loadResult.extension !== 'json-ld') {
    throw new Error('only json-ld schema is supported');
  }
  const toHash = new Uint8Array([
    ...loadResult.schema,
    ...toBytes(query.Schema.type),
  ]);

  const schemaHash = keccak256(toHash);

  // only json ld-schema are supported
  const cq = parseRequest(
    query.Req,
    loadResult.schema,
    query.Schema.type,
    outputs.value.length,
  );

  if (outputs.operator !== cq.operator) {
    throw new Error(`operator that was used is not equal to request`);
  }

  if (outputs.slotIndex !== cq.slotIndex) {
    throw new Error(`wrong claim slot was used in claim`);
  }

  if (outputs.operator !== cq.operator) {
    throw new Error(`operator that was used is not equal to request`);
  }
  for (let index = 0; index < cq.values.length; index++) {
    if (outputs.value[index].toString(10) !== cq.values[index].toString(10)) {
      throw new Error(
        `comparison value that was used is not equal to requested in query`,
      );
    }
  }

  if (!schemaHash.equals(Buffer.from(Core.intToBytes(outputs.schemaHash)))) {
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
  let fieldName = '';
  let fieldReq: Map<string, unknown>;
  if (req.keys.length > 1) {
    throw new Error(`multiple requests  not supported`);
  }

  for (const [key, value] of req.entries()) {
    console.log(key, value);
    fieldName = key;

    const fieldReq = value as Map<string, unknown>;
    if (fieldReq.keys.length > 1) {
      throw new Error(`multiple predicates for one field not supported`);
    }
    break;
  }

  const slotIndex = getFieldSlotIndex(fieldName, credType, schema);

  let operator: number;
  const values: bigint[] = new Array<bigint>(valueLength);
  for (const [key, value] of fieldReq.entries()) {
    console.log(key, value);
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
  const obj = JSON.parse(schema.toString());
  const type = nestedProperty.get(
    obj,
    `@context.[0].${credentialType}.@context.${fieldName}.@type`,
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
