import { promises as fs } from 'fs';

export interface IKeyLoader {
  load(circuitId: string): Promise<Buffer>;
}

export class FSKeyLoader implements IKeyLoader {
  constructor(public readonly dir: string) {}
  public async load(curcuitId: string): Promise<Buffer> {
    const data = await fs.readFile(`${this.dir}/${curcuitId}.json`, 'utf8');
    return Buffer.from(data);
  }
}
