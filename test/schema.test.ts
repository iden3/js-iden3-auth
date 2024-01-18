import { DocumentLoader, getDocumentLoader } from '@iden3/js-jsonld-merklization';

describe('schema loader', () => {
  it('schema http loader', async () => {
    const url =
      'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld';

    const loader: DocumentLoader = getDocumentLoader();
    const schemaResult = (await loader(url)).document;
    expect(schemaResult).not.toBeNull();
    expect(schemaResult).toBeDefined();
  });

  it('schema ipfs loader', async () => {
    let connectionString = process.env.IPFS_URL;
    if (!connectionString) {
      connectionString = 'https://ipfs.io';
    }
    const loader = getDocumentLoader({
      ipfsNodeURL: connectionString
    });
    const schemaResult = (await loader('ipfs://Qmb1Q5jLETkUkhswCVX52ntTCNQnRm3NyyGf1NZG98u5cv'))
      .document;
    expect(schemaResult).not.toBeNull();
    expect(schemaResult).toBeDefined();
  });
});
