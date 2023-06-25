import { getDocumentLoader } from '@iden3/js-jsonld-merklization';

export interface SchemaLoadResult {
  schema: Uint8Array;
  extension: string;
}

export interface ISchemaLoader {
  load(URL: string): Promise<SchemaLoadResult>;
}

export class UniversalSchemaLoader implements ISchemaLoader {
  constructor(private ipfsUrl: string) {}
  public async load(url: string): Promise<SchemaLoadResult> {
    const l = getDocumentLoader({
      ipfsNodeURL: this.ipfsUrl ?? null,
    });
    const schemaRes = (await l(url)).document;
    return {
      schema: new TextEncoder().encode(JSON.stringify(schemaRes)),
      extension: 'json-ld',
    };
  }
}
