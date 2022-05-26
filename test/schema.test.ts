import { HttpSchemaLoader, IpfsSchemaLoader } from '../src/loaders/schema';

test('schema http loader', async () => {
  const url =
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld';
  const loader = new HttpSchemaLoader(url);
  const schemaResult = await loader.load();
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});

test('schema ipfs loader', async () => {
  const url =
    'https://ipfs.infura.io:5001';
  const cId = 'QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP';
  const loader = new IpfsSchemaLoader(url, cId);
  const schemaResult = await loader.load();
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});
