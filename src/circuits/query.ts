import { ISchemaLoader, SchemaLoadResult } from '@lib/loaders/schema';
import nestedProperty from 'nested-property';
import { Id, SchemaHash, DID } from '@iden3/js-iden3-core';
import { Merkelizer, Path } from '@iden3/js-jsonld-merklization';
import keccak256 from 'keccak256';

const operators: Map<string, number> = new Map([
  ['$noop', 0],
  ['$eq', 1],
  ['$lt', 2],
  ['$gt', 3],
  ['$in', 4],
  ['$nin', 5],
  ['$ne', 6],
]);

const serializationIndexDataSlotAType = 'serialization:IndexDataSlotA';
const serializationIndexDataSlotBType = 'serialization:IndexDataSlotB';

const serializationValueDataSlotAType = 'serialization:ValueDataSlotA';
const serializationValueDataSlotBType = 'serialization:ValueDataSlotB';

// Query is a query to circuit
export interface Query {
  allowedIssuers: string[];
  credentialSubject: Map<string, unknown>;
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
  schemaLoader: ISchemaLoader,
  verifiablePresentation?: JSON,
): Promise<void> {
  // validate issuer
  let userDID: DID;
  try {
    userDID = DID.parseFromId(outputs.issuerId);
  } catch (e) {
    throw new Error("invalid issuerId in circuit's output");
  }
  const issuerAllowed = query.allowedIssuers.some(
    (issuer) => issuer === '*' || issuer === userDID.toString(),
  );
  if (!issuerAllowed) {
    throw new Error('issuer is not in allowed list');
  }

  // validate schema
  let loadResult: SchemaLoadResult;
  try {
    loadResult = await schemaLoader.load(query.context);
  } catch (e) {
    throw new Error(`can't load schema for request query`);
  }
  const schemaHash = createSchemaHash(query.context, query.type);
  if (schemaHash.toString() !== outputs.schemaHash.toString()) {
    throw new Error(`schema that was used is not equal to requested in query`);
  }

  if (!query.skipClaimRevocationCheck && outputs.isRevocationChecked === 0) {
    throw new Error(`check revocation is required`);
  }

  const cq = await parseRequest(
    query.credentialSubject,
    loadResult.schema,
    query.context,
    query.type,
    outputs.value.length,
    outputs.merklized,
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

  for (let index = 0; index < cq.values.length; index++) {
    if (outputs.value[index].toString(10) !== cq.values[index].toString(10)) {
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

  for (let index = 1; index < cq.values.length; index++) {
    if (outputs.value[index].toString(10) !== '0') {
      throw new Error(`selective disclosure not available for array of values`);
    }
  }

  let mz: Merkelizer;
  const strVerifiablePresentation: string = verifiablePresentation.toString();
  try {
    mz = await Merkelizer.merkelizeJSONLD(strVerifiablePresentation);
  } catch (e) {
    throw new Error(`can't merkelize verifiablePresentation`);
  }

  let merkalizedPath: Path;
  try {
    merkalizedPath = await Path.newPathFromCtx(
      strVerifiablePresentation,
      `verifiableCredential.${cq.fieldName}`,
    );
  } catch (e) {
    throw new Error(`can't build path to '${cq.fieldName}' key`);
  }

  let valueByPath: any;
  try {
    valueByPath = mz.rawValue(merkalizedPath);
  } catch (e) {
    throw new Error(`can't get value by path '${cq.fieldName}'`);
  }

  const mvValue = mz.mkValue(valueByPath);

  if (mvValue.toString(10) !== outputs.value[0].toString(10)) {
    throw new Error(`value that was used is not equal to requested in query`);
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
      isSelectiveDisclosure: false,
      fieldName: '',
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
  if (merkalized === 1) {
    const txtSchema = new TextDecoder().decode(schema);
    const path = await Path.getContextPathKey(txtSchema, credType, fieldName);
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
    isSelectiveDisclosure: false,
    fieldName,
  };

  if (Object.keys(fieldReq).length === 0) {
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

// TODO (illia-korotia): move to core like static method or contructor of SchemaHash type.
export function createSchemaHash(
  schemaContext: string,
  type: string,
): SchemaHash {
  const schemaID = new TextEncoder().encode(`${schemaContext}#${type}`);
  const bytes = new Uint8Array([...schemaID]);
  const h = keccak256(Buffer.from(bytes));
  return new SchemaHash(h.slice(-16));
}
