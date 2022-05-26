import axios from 'axios';
import { TextDecoder, TextEncoder } from 'util';
import { create, IPFSHTTPClient } from 'ipfs-http-client';
import { Schema } from 'protocol/models';
import { Script } from 'vm';

export type SchemaLoadResult = {
  schema: Uint8Array;
  extension: string;
};

export interface ISchemaLoader {
  load(schema: Schema): Promise<SchemaLoadResult>;
}

export class UniversalSchemaLoader implements ISchemaLoader {
  private ipfsUrl: string;
  constructor(ipfsUrl: string) {
    this.ipfsUrl = ipfsUrl;
  }
  public async load(schema: Schema): Promise<SchemaLoadResult> {
    let l = getLoader(schema.url);
    let schemaRes = await l.load(schema);
    return schemaRes;
  }
}

export class HttpSchemaLoader implements ISchemaLoader {
  constructor() {}
  public async load(schema: Schema): Promise<SchemaLoadResult> {
    const resp = await axios.get(schema.url);

    const schemaBytes = new TextEncoder().encode(JSON.stringify(resp.data));

    return {
      schema: schemaBytes,
      extension: 'json-ld',
    };
  }
}
export class IpfsSchemaLoader implements ISchemaLoader {
  private readonly client: IPFSHTTPClient;
  constructor(private readonly url: string) {
    this.client = create({ url: this.url });
  }
  public async load(schema: Schema): Promise<SchemaLoadResult> {
    const uri = new URL(schema.url);

    const schemaRes = await this.client.cat(uri.host);

    let schemaBytes: Uint8Array;
    for await (const num of schemaRes) {
      schemaBytes = Uint8Array.from(num);
    }

    return {
      schema: schemaBytes,
      extension: 'json-ld',
    };
  }
}

// TODO: IPFS URL FOR BROWSER
export function getLoader(url: string, ipfsConfigUrl?: string): ISchemaLoader {
  const uri = new URL(url);

  switch (uri.protocol) {
    case 'http':
    case 'https':
      return new HttpSchemaLoader();
    case 'ipfs':
      return new IpfsSchemaLoader(ipfsConfigUrl);

    default:
      throw new Error(`Loader not provided for given url, ${url}`);
  }
}
