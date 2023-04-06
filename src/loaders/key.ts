import * as fs from 'fs';

export interface IKeyLoader {
  load(circuitId: string): Promise<Uint8Array>;
}

export class FSKeyLoader implements IKeyLoader {
  constructor(public readonly dir: string) {}
  public async load(circuitId: string): Promise<Uint8Array> {
    const data = fs.readFileSync(`${this.dir}/${circuitId}.json`, 'utf8');
    const enc = new TextEncoder();
    return enc.encode(data);
  }
}
