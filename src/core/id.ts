// eslint-disable-next-line camelcase
import { binary_to_base58, base58_to_binary } from 'base58-js';
import { Core } from '@lib/core/core';
import { fromLittleEndian } from '@lib/core/util';

// ID is a byte array with
// [  type  | root_genesis | checksum ]
// [2 bytes |   27 bytes   | 2 bytes  ]
// where the root_genesis are the first 28 bytes from the hash root_genesis

export class Id {
  private _bytes: Uint8Array;

  constructor(typ: Uint8Array, genesis: Uint8Array) {
    const checksum: Uint8Array = Core.calculateChecksum(typ, genesis);
    this._bytes = Uint8Array.from([...typ, ...genesis, ...checksum]);
  }

  static fromBytes(bytes: Uint8Array): Id {
    const { typ, genesis }: { typ: Uint8Array; genesis: Uint8Array } =
      Core.decomposeBytes(bytes);
    return new Id(typ, genesis);
  }

  string(): string {
    return binary_to_base58(this._bytes);
  }

  bytes(): Uint8Array {
    return this._bytes;
  }

  bigInt(): bigint {
    return fromLittleEndian(this._bytes);
  }

  equal(id: Id): boolean {
    return JSON.stringify(this._bytes) === JSON.stringify(id.bytes);
  }

  static idFromBytes(b: Uint8Array): Id {
    const bytes = b ?? Uint8Array.from([]);
    if (bytes.length !== 31) {
      throw new Error('IDFromBytes error: byte array incorrect length');
    }

    if (bytes.every((i: number) => i === 0)) {
      throw new Error('IDFromBytes error: byte array empty');
    }

    const id = Id.fromBytes(bytes);

    if (!Core.checkChecksum(bytes)) {
      throw new Error('IDFromBytes error: checksum error');
    }

    return id;
  }

  static idFromString(s: string): Id {
    const bytes = base58_to_binary(s);
    return Id.idFromBytes(bytes);
  }

  static idFromInt(bigInt: bigint): Id {
    const b = Core.intToBytes(bigInt);
    return Id.idFromBytes(b);
  }
}
