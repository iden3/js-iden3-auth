import { HttpSchemaLoader, IpfsSchemaLoader } from '@lib/loaders/schema';
import { Schema } from '@lib/protocol/models';

test('schema http loader', async () => {
  const url =
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld';

  const schema: Schema = { url: url, type: 'KYCCountryOfResidenceCredential' };
  const loader = new HttpSchemaLoader();
  const schemaResult = await loader.load(schema);
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});

test('schema ipfs loader', async () => {
  const url = 'https://ipfs.infura.io:5001';
  const schema: Schema = {
    url: 'ipfs://QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP',
    type: 'KYCCountryOfResidenceCredential',
  };

  const loader = new IpfsSchemaLoader(url);
  const schemaResult = await loader.load(schema);
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});
