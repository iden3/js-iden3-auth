import { Poseidon } from '@iden3/js-crypto';
import { Bytes, Hasher } from '../types';
import { Constants } from '@iden3/js-iden3-core';

class PoseidonHasher implements Hasher {
  Hash(inp: bigint[]): Promise<bigint> {
    return Promise.resolve(Poseidon.hash(inp));
  }

  HashBytes(b: Bytes): Promise<bigint> {
    return Promise.resolve(Poseidon.hashBytes(b));
  }

  Prime(): bigint {
    return Constants.Q;
  }
}

export default PoseidonHasher;
