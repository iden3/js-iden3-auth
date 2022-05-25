import { promises as fs } from "fs";

export interface IKeyLoader {
   load (curcuitId: string): Promise<Buffer>;
}


export class FSKeyLoader implements IKeyLoader{
    dir:string;
    constructor(_dir:string) {
        this.dir = _dir;
    }
    public  async load(curcuitId :string): Promise<Buffer> {
        const data = await fs.readFile(`${this.dir}/${curcuitId}.json`,'utf8');
        return Buffer.from(data);
      }
}