import { checkQueryRequest, ClaimOutputs, Query } from '@lib/circuits/query';
import { getUnixTimestamp, Id, SchemaHash } from '@iden3/js-iden3-core';
import { byteEncoder, cacheLoader, createSchemaHash } from '@0xpolygonid/js-sdk';

const defaultLoader = cacheLoader();
const vpEmployee = JSON.parse(`{
	"@type": "VerifiablePresentation",
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"verifiableCredential": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld"
		],
		"@type": [
			"VerifiableCredential",
			"KYCEmployee"
		],
		"credentialSubject": {
			"@type": "KYCEmployee",
			"position": "SSI Consultant"
		}
	}
}`);

const vp = JSON.parse(`{
	"@context": [
		"https://www.w3.org/2018/credentials/v1"
	],
	"@type": "VerifiablePresentation",
	"verifiableCredential": {
		"@context": [
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
		],
		"@type": ["VerifiableCredential","KYCCountryOfResidenceCredential"],
		"credentialSubject": {
			"type": "KYCCountryOfResidenceCredential",
			"countryCode": 800
		}
	}
}`);

const issuerDID = 'did:polygonid:polygon:mumbai:2qHSHBGWGJ68AosMKcLCTp8FYdVrtYE6MtNHhq8xpK';
const issuerID = Id.fromBigInt(
  BigInt('22638457188543025296541325416907897762715008870723718557276875842936181250')
);
const KYCCountrySchema = SchemaHash.newSchemaHashFromInt(
  BigInt('336615423900919464193075592850483704600')
);
const KYCEmployeeSchema = SchemaHash.newSchemaHashFromInt(
  BigInt('219578617064540016234161640375755865412')
);
const BigIntTrueHash = BigInt(
  '18586133768512220936620570745912940619677854269274689475585506675881198879027'
);
const KYCAgeNonMerklizedSchema = createSchemaHash(
  byteEncoder.encode(
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld#KYCAgeCredential'
  )
);

test('Check merklized query', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: { $nin: [800] }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 5,
    value: new Array(BigInt(800)),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader)).resolves.not.toThrow();
});

test('Check non-merklized query', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      birthday: { $eq: [19960424] }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
    type: 'KYCAgeCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCAgeNonMerklizedSchema,
    claimPathKey: BigInt(0),
    operator: 1,
    value: new Array(BigInt(19960424)),
    merklized: 0,
    slotIndex: 2,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader)).resolves.not.toThrow();
});

test('Selective disclosure', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt(800)),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader, vp)).resolves.not.toThrow();
});

test('Query with boolean type', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      ZKPexperiance: {
        $eq: true
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '1944808975288007371356450257872165609440470546066507760733183342797918372827'
    ),
    operator: 1,
    value: new Array(BigIntTrueHash),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader)).resolves.not.toThrow();
});

test('Selective disclosure with xsd:string type', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      position: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '15406634529806189041952040954758558497189093183268091368437514469450172572054'
    ),
    operator: 1,
    value: new Array(
      BigInt('957410455271905675920624030785024750144198809104092676617070098470852489834')
    ),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader, vpEmployee)).resolves.not.toThrow();
});

test('EQ operator for xsd:string type', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      position: {
        $eq: 'Software Engineer'
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '15406634529806189041952040954758558497189093183268091368437514469450172572054'
    ),
    operator: 1,
    value: new Array(
      BigInt('7481731651336040098616464366227645531920423822088928207225802836605991806542')
    ),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  await expect(checkQueryRequest(query, pubSig, defaultLoader)).resolves.not.toThrow();
});

test('Empty disclosure JSON for disclosure request', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      'failed to validate selective disclosure: no vp present in selective disclosure request'
    );
  }
});

test('Not EQ operation for disclosure request', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 5,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader, vp)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      'failed to validate selective disclosure: operator for selective disclosure must be $eq'
    );
  }
});

test('Not array of values for disclosure request', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: [BigInt('800'), BigInt('801')],
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader, vp)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      'failed to validate selective disclosure: selective disclosure not available for array of values'
    );
  }
});

test('Proof was generated for another disclosure value', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('1')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader, vp)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      'failed to validate selective disclosure: value that was used is not equal to requested in query'
    );
  }
});

test('Different key between proof and disclosure response', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      documentType: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader, vp)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      `failed to validate selective disclosure: can't get merkle value for field 'documentType'`
    );
  }
});

test('Invalid issuer', async () => {
  const query: Query = {
    allowedIssuers: ['123'],
    credentialSubject: {
      documentType: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`issuer is not in allowed list`);
  }
});

test('Invalid Schema ID', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      documentType: {
        $eq: 3
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCAgeCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('3')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`schema that was used is not equal to requested in query`);
  }
});

test('Multiply query', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      documentType: {},
      countryCode: {}
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`multiple requests not supported`);
  }
});

test('Multiple predicates in one request', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      countryCode: {
        $eq: 20,
        $ne: 10
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`multiple predicates for one field not supported`);
  }
});

test('Proof was generated for another query operator', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      countryCode: {
        $eq: 20
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 3,
    value: new Array(BigInt('800')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      `failed to validate operators: operator that was used is not equal to request`
    );
  }
});

test('failed to validate operators: comparison value that was used is not equal to requested in query', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      countryCode: {
        $nin: [20]
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 5,
    value: new Array(BigInt('40')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      `failed to validate operators: comparison value that was used is not equal to requested in query`
    );
  }
});

test('Different slot index', async () => {
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      birthday: { $eq: [19960424] }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
    type: 'KYCAgeCredential'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCAgeNonMerklizedSchema,
    claimPathKey: BigInt(0),
    operator: 1,
    value: new Array(BigInt(19960424)),
    merklized: 0,
    slotIndex: 3,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`wrong claim slot was used in claim`);
  }
});

test('Check revocation is required', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      countryCode: {
        $nin: [20]
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    type: 'KYCCountryOfResidenceCredential',
    skipClaimRevocationCheck: false
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCCountrySchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 5,
    value: new Array(BigInt('20')),
    merklized: 1,
    isRevocationChecked: 0,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`check revocation is required`);
  }
});

test('Unsupported lt operator for xsd:boolean', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      ZKPexperiance: {
        $lt: true
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 2,
    value: new Array(BigInt('20')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      `operator '$lt' is not supported for 'http://www.w3.org/2001/XMLSchema#boolean' datatype`
    );
  }
});

test('Negative value in request', async () => {
  const query: Query = {
    allowedIssuers: [issuerDID],
    credentialSubject: {
      documentType: {
        $eq: -1
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '17002437119434618783545694633038537380726339994244684348913844923422470806844'
    ),
    operator: 1,
    value: new Array(BigInt('-1')),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: getUnixTimestamp(new Date())
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(
      `failed to validate operators: comparison value that was used is not equal to requested in query`
    );
  }
});

test('Generated proof is outdated', async () => {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  yesterday.setMinutes(yesterday.getMinutes() - 1);
  const query: Query = {
    allowedIssuers: ['*'],
    credentialSubject: {
      ZKPexperiance: {
        $eq: true
      }
    },
    context:
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
    type: 'KYCEmployee'
  };
  const pubSig: ClaimOutputs = {
    issuerId: issuerID,
    schemaHash: KYCEmployeeSchema,
    claimPathKey: BigInt(
      '1944808975288007371356450257872165609440470546066507760733183342797918372827'
    ),
    operator: 1,
    value: new Array(BigIntTrueHash),
    merklized: 1,
    isRevocationChecked: 1,
    valueArraySize: 64,
    timestamp: yesterday.getTime() / 1000
  };
  try {
    expect(await checkQueryRequest(query, pubSig, defaultLoader)).toThrowError();
  } catch (e) {
    expect((e as Error).message).toBe(`generated proof is outdated`);
  }
});
