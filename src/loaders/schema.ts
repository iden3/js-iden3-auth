import axios from 'axios';
import { TextDecoder, TextEncoder } from 'util';
import { create, IPFSHTTPClient } from 'ipfs-http-client';

export type SchemaLoadResult = {
  schema: Uint8Array;
  extension: string;
};

export interface ISchemaLoader {
  load(): Promise<SchemaLoadResult>;
}

export class HttpSchemaLoader implements ISchemaLoader {
  constructor(private readonly url: string) {}
  public async load(): Promise<SchemaLoadResult> {
    const resp = await axios.get(this.url);

    const schema = new TextEncoder().encode(JSON.stringify(resp.data));

    return {
      schema,
      extension: 'json-ld',
    };
  }
}
export class IpfsSchemaLoader implements ISchemaLoader {
  private readonly client: IPFSHTTPClient;
  constructor(private readonly url: string, private readonly cId: string) {
    this.client = create({ url: this.url });
  }
  public async load(): Promise<SchemaLoadResult> {
    const schemaRes = await this.client.cat(this.cId);

    let schema: Uint8Array;
    for await (const num of schemaRes) {
      schema = Uint8Array.from(num);
    }

    return {
      schema,
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
      return new HttpSchemaLoader(url);
    case 'ipfs':
      return new IpfsSchemaLoader(ipfsConfigUrl, uri.host);

    default:
      throw new Error(`Loader not provided for given url, ${url}`);
  }
}
