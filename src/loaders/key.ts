import { promises as fs } from 'fs';
import { TextEncoder } from 'util';

export interface IKeyLoader {
  load(circuitId: string): Promise<Uint8Array>;
}

export class FSKeyLoader implements IKeyLoader {
  constructor(public readonly dir: string) {}
  public async load(curcuitId: string): Promise<Uint8Array> {
    const data = await fs.readFile(`${this.dir}/${curcuitId}.json`, 'utf8');
    const enc = new TextEncoder();
    return enc.encode(data);
  }
}
