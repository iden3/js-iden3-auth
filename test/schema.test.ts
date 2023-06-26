import {
  DocumentLoader,
  getDocumentLoader,
} from '@iden3/js-jsonld-merklization';

test('schema http loader', async () => {
  const url =
    'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld';

  const loader: DocumentLoader = getDocumentLoader();
  const schemaResult = (await loader(url)).document;
  expect(schemaResult).not.toBeNull();
  expect(schemaResult).toBeDefined();
});

test('schema ipfs loader', async () => {
  let connectionString = process.env.IPFS_URL;
  if (!connectionString) {
    connectionString = 'https://ipfs.io';
  }
  const loader = getDocumentLoader({
    ipfsGatewayURL: connectionString,
  });
  const schemaResult = (
    await loader('ipfs://QmP8NrKqoBKjmKwMsC8pwBCBxXR2PhwSepwXx31gnJxAbP')
  ).document;
  expect(schemaResult).not.toBeNull();
  expect(schemaResult).toBeDefined();
});
