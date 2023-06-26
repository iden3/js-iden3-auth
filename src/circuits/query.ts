import nestedProperty from 'nested-property';
import { Id, SchemaHash, DID } from '@iden3/js-iden3-core';
import {
  Merklizer,
  Path,
  MtValue,
  getDocumentLoader,
} from '@iden3/js-jsonld-merklization';
import { Proof } from '@iden3/js-merkletree';
import keccak256 from 'keccak256';
import * as xsdtypes from 'jsonld/lib/constants';
import { DocumentLoader } from '@iden3/js-jsonld-merklization/dist/types/loaders/jsonld-loader';
import { byteEncoder } from '@0xpolygonid/js-sdk';

const bytesDecoder = new TextDecoder();

const operators: Map<string, number> = new Map([
  ['$noop', 0],
  ['$eq', 1],
  ['$lt', 2],
  ['$gt', 3],
  ['$in', 4],
  ['$nin', 5],
  ['$ne', 6],
]);

const allOperations: Set<number> = new Set(operators.values());

const availableTypesOperators: Map<string, Set<number>> = new Map([
  [xsdtypes.XSD_BOOLEAN, new Set([operators.get('$eq'), operators.get('$ne')])],
  [xsdtypes.XSD_INTEGER, allOperations],
  [xsdtypes.XSD_INTEGER + 'nonNegativeInteger', allOperations],
  [xsdtypes.XSD_INTEGER + 'positiveInteger', allOperations],
  [
    xsdtypes.XSD_STRING,
    new Set([
      operators.get('$eq'),
      operators.get('$ne'),
      operators.get('$in'),
      operators.get('$nin'),
    ]),
  ],
  [xsdtypes.XSD_DATE, allOperations],
]);

const serializationIndexDataSlotAType = 'serialization:IndexDataSlotA';
const serializationIndexDataSlotBType = 'serialization:IndexDataSlotB';

const serializationValueDataSlotAType = 'serialization:ValueDataSlotA';
const serializationValueDataSlotBType = 'serialization:ValueDataSlotB';

// Query is a query to circuit
export interface Query {
  allowedIssuers: string[];
  credentialSubject: { [key: string]: unknown };
  context: string;
  type: string;
  claimID?: string;
  skipClaimRevocationCheck?: boolean;
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
}

export async function checkQueryRequest(
  query: Query,
  outputs: ClaimOutputs,
  schemaLoader?: DocumentLoader,
  verifiablePresentation?: JSON,
): Promise<void> {
  // validate issuer
  const userDID = DID.parseFromId(outputs.issuerId);
  const issuerAllowed = query.allowedIssuers.some(
    (issuer) => issuer === '*' || issuer === userDID.toString(),
  );
  if (!issuerAllowed) {
    throw new Error('issuer is not in allowed list');
  }

  // validate schema
  let schema: object;
  try {
    const loader = schemaLoader ?? getDocumentLoader();
    schema = (await loader(query.context)).document;
  } catch (e) {
    throw new Error(`can't load schema for request query`);
  }

  const schemaId: string = await Path.getTypeIDFromContext(
    JSON.stringify(schema),
    query.type,
  );
  const schemaHash = createSchemaHash(schemaId);
  if (schemaHash.bigInt() !== outputs.schemaHash.bigInt()) {
    throw new Error(`schema that was used is not equal to requested in query`);
  }

  if (!query.skipClaimRevocationCheck && outputs.isRevocationChecked === 0) {
    throw new Error(`check revocation is required`);
  }

  const cq = await parseRequest(
    query,
    outputs,
    byteEncoder.encode(JSON.stringify(schema)),
  );

  // validate selective disclosure
  if (cq.isSelectiveDisclosure) {
    try {
      await validateDisclosure(verifiablePresentation, cq, outputs);
    } catch (e) {
      throw new Error(`failed to validate selective disclosure: ${e.message}`);
    }
  } else {
    try {
      await validateOperators(cq, outputs);
    } catch (e) {
      throw new Error(`failed to validate operators: ${e.message}`);
    }
  }

  // verify claim
  if (outputs.merklized === 1) {
    if (outputs.claimPathKey !== cq.claimPathKey) {
      throw new Error(`proof was generated for another path`);
    }
    if (outputs.claimPathNotExists === 1) {
      throw new Error(`proof doesn't contains target query key`);
    }
  } else {
    if (outputs.slotIndex !== cq.slotIndex) {
      throw new Error(`wrong claim slot was used in claim`);
    }
  }

  return;
}

async function validateOperators(cq: CircuitQuery, outputs: ClaimOutputs) {
  if (outputs.operator !== cq.operator) {
    throw new Error(`operator that was used is not equal to request`);
  }
  if (outputs.operator === operators.get('$noop')) {
    // for noop operator slot and value are not used in this case
    return;
  }

  for (let index = 0; index < outputs.value.length; index++) {
    if (outputs.value[index] !== cq.values[index]) {
      throw new Error(
        `comparison value that was used is not equal to requested in query`,
      );
    }
  }
}

async function validateDisclosure(
  verifiablePresentation: JSON,
  cq: CircuitQuery,
  outputs: ClaimOutputs,
) {
  if (!verifiablePresentation) {
    throw new Error(
      `verifiablePresentation is required for selective disclosure request`,
    );
  }

  if (outputs.operator !== operators.get('$eq')) {
    throw new Error(`operator for selective disclosure must be $eq`);
  }

  for (let index = 1; index < outputs.value.length; index++) {
    if (outputs.value[index] !== 0n) {
      throw new Error(`selective disclosure not available for array of values`);
    }
  }

  let mz: Merklizer;
  const strVerifiablePresentation: string = JSON.stringify(
    verifiablePresentation,
  );
  try {
    mz = await Merklizer.merklizeJSONLD(strVerifiablePresentation);
  } catch (e) {
    throw new Error(`can't merkelize verifiablePresentation`);
  }

  let merklizedPath: Path;
  try {
    const p = `verifiableCredential.credentialSubject.${cq.fieldName}`;
    merklizedPath = await Path.fromDocument(null, strVerifiablePresentation, p);
  } catch (e) {
    throw new Error(`can't build path to '${cq.fieldName}' key`);
  }

  let proof: Proof;
  let value: MtValue;
  try {
    ({ proof, value } = await mz.proof(merklizedPath));
  } catch (e) {
    throw new Error(`can't get value by path '${cq.fieldName}'`);
  }

  if (!proof.existence) {
    throw new Error(
      `path [${merklizedPath.parts}] doesn't exist in verifiablePresentation document`,
    );
  }

  const bi = await value.mtEntry();
  if (bi !== outputs.value[0]) {
    throw new Error(`value that was used is not equal to requested in query`);
  }

  return;
}

async function parseRequest(
  query: Query,
  outputs: ClaimOutputs,
  schema: Uint8Array,
): Promise<CircuitQuery> {
  if (!query.credentialSubject) {
    return {
      operator: operators.get('$noop'),
      values: null,
      slotIndex: 0,
      isSelectiveDisclosure: false,
      fieldName: '',
    };
  }
  if (Object.keys(query.credentialSubject).length > 1) {
    throw new Error(`multiple requests not supported`);
  }

  const txtSchema = bytesDecoder.decode(schema);

  let fieldName: string;
  let predicate: Map<string, unknown>;

  for (const [key, value] of Object.entries(query.credentialSubject)) {
    fieldName = key;

    predicate = value as Map<string, unknown>;

    if (Object.keys(predicate).length > 1) {
      throw new Error(`multiple predicates for one field not supported`);
    }
    break;
  }

  let datatype: string;
  if (fieldName !== '') {
    datatype = await Path.newTypeFromContext(
      txtSchema,
      `${query.type}.${fieldName}`,
    );
  }

  const [operator, values] = await parsePredicate(predicate, datatype);
  const zeros: Array<bigint> = Array.from({
    length: outputs.valueArraySize - values.length,
  }).fill(BigInt(0)) as Array<bigint>;
  const fullArray: Array<bigint> = values.concat(zeros);

  const [claimPathKey, slotIndex] = await verifyClaim(
    outputs.merklized,
    txtSchema,
    query.type,
    fieldName,
  );

  const cq: CircuitQuery = {
    claimPathKey,
    slotIndex,
    operator,
    values: fullArray,
    isSelectiveDisclosure: false,
    fieldName,
  };

  if (Object.keys(predicate).length === 0) {
    cq.isSelectiveDisclosure = true;
  }

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
  isSelectiveDisclosure: boolean;
  fieldName: string;
};

export function createSchemaHash(schemaId: string): SchemaHash {
  const h = keccak256(schemaId);
  return new SchemaHash(h.slice(-16));
}

async function getValuesAsArray(v: any, datatype: string): Promise<bigint[]> {
  const values: Array<bigint> = [];
  if (Array.isArray(v)) {
    for (let index = 0; index < v.length; index++) {
      if (!isPositiveInteger(v[index])) {
        throw new Error(`value must be positive integer`);
      }
      values[index] = await Merklizer.hashValue(datatype, v[index]);
    }
    return values;
  }

  if (!isPositiveInteger(v)) {
    throw new Error(`value must be positive integer`);
  }
  values[0] = await Merklizer.hashValue(datatype, v);
  return values;
}

function isPositiveInteger(value: any): boolean {
  if (!Number.isInteger(value)) {
    return true;
  }
  return value >= 0;
}

function isValidOperation(datatype: string, op: number): boolean {
  if (op === operators.get('$noop')) {
    return true;
  }

  if (!availableTypesOperators.has(datatype)) {
    return false;
  }
  const ops = availableTypesOperators.get(datatype);

  return ops.has(op);
}

async function verifyClaim(
  merklized: number,
  txtSchema: string,
  credType: string,
  fieldName: string,
): Promise<[bigint, number]> {
  let slotIndex: number;
  let claimPathKey: bigint;
  if (merklized === 1) {
    const path = await Path.getContextPathKey(txtSchema, credType, fieldName);
    path.prepend(['https://www.w3.org/2018/credentials#credentialSubject']);
    claimPathKey = await path.mtEntry();
  } else {
    slotIndex = getFieldSlotIndex(
      fieldName,
      credType,
      new TextEncoder().encode(txtSchema),
    );
  }

  return [claimPathKey, slotIndex];
}

async function parsePredicate(
  predicate: Map<string, any>,
  datatype: string,
): Promise<[number, bigint[]]> {
  let operator: number;
  let values: bigint[] = [];
  for (const [key, value] of Object.entries(predicate)) {
    if (!operators.has(key)) {
      throw new Error(`operator is not supported by lib`);
    }
    operator = operators.get(key);
    if (!isValidOperation(datatype, operator)) {
      throw new Error(
        `operator '${operator}' is not supported for '${datatype}' datatype`,
      );
    }

    values = await getValuesAsArray(value, datatype);
    break;
  }
  return [operator, values];
}
