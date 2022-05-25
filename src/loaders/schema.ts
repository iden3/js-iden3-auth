import { promises as fs } from 'fs';
import { type } from 'os';
import { Schema } from 'protocol/models';

export interface ISchemaLoader {
  load(schema: Schema): Promise<SchemaLoadResult>;
}

export class DefaultSchemaLoader implements ISchemaLoader {
  private ipfsUrl: string;
  constructor(ipfsUrl: string) {
    this.ipfsUrl = ipfsUrl;
  }
  public async load(schema: Schema): Promise<SchemaLoadResult> {
    // TODO: implement schema loader for IPFS and HTTPS.

    const url = new URL('http://example.com/path/index.html');
    
    
    let res: SchemaLoadResult = { schema: null, extension: 'json-ld' };
    return res;
  }
}
export type SchemaLoadResult = {
  schema: Uint8Array;
  extension: string;
};
