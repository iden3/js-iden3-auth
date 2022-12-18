import { HttpSchemaLoader, IpfsSchemaLoader } from '@lib/loaders/schema';

test('schema http loader', async () => {
  const url =
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld';

  const loader = new HttpSchemaLoader();
  const schemaResult = await loader.load(url);
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});

test('schema ipfs loader', async () => {
  let connectionString = process.env.IPFS_URL;
  if (connectionString === undefined) {
    connectionString = 'https://ipfs.io';
  }
  const loader = new IpfsSchemaLoader(connectionString);
  const schemaResult = await loader.load(
    'ipfs://QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP',
  );
  expect(schemaResult.extension).toEqual('json-ld');
  expect(schemaResult.schema).not.toBeNull();
});
