import { promises as fs } from 'fs';

export interface IKeyLoader {
  load(circuitId: string): Promise<Object>;
}

export class FSKeyLoader implements IKeyLoader {
  constructor(public readonly dir: string) {}
  public async load(curcuitId: string): Promise<Object> {
    const data = await fs.readFile(`${this.dir}/${curcuitId}.json`, 'utf8');
    return  JSON.parse(data);

  }
}
