// eslint-disable-next-line camelcase
import { binary_to_base58, base58_to_binary } from 'base58-js';
import { toBigIntLE } from 'bigint-buffer';
import { Core } from './core.js';

// ID is a byte array with
// [  type  | root_genesis | checksum ]
// [2 bytes |   27 bytes   | 2 bytes  ]
// where the root_genesis are the first 28 bytes from the hash root_genesis

export class Id {
    #bytes = [];
    constructor(typ, genesis) {
        const checksum = Core.calculateChecksum(typ, genesis);
        this.#bytes = Uint8Array.from([...typ, ...genesis, ...checksum]);
    }

    static fromBytes(bytes) {
        const { typ, genesis } = Core.decomposeBytes(bytes);
        return new Id(typ, genesis);
    }

    /**
    * String returns a base58 from the ID
     * @returns {string}
     */
    string() {
        return binary_to_base58(Uint8Array.from(this.#bytes));
    }

    /**
     * Bytes returns the bytes from the ID
     * @returns {Uint8Array}
     */
    bytes() {
        return this.#bytes;
    }

    /**
     * bigInt
     * @returns {bigint}
     */
    bigInt() {
        return toBigIntLE(Buffer.from(this.#bytes));
    }

    /**
     *Equal
     * @param {bytes[]} id
     */
    equal(id) {
        return JSON.stringify(this.#bytes) === JSON.stringify(id);
    }

    /**
     *
     * @param {*} b
     *  @return {*}
    */
    static idFromBytes(b) {
        const bytes = b ?? [];
        if (bytes.length !== 31) {
            throw new Error('IDFromBytes error: byte array incorrect length');
        }

        if (bytes.every((i) => i === 0)) {
            throw new Error('IDFromBytes error: byte array empty');
        }

        const id = Id.fromBytes(bytes);

        if (!Core.checkChecksum(bytes)) {
            throw new Error('IDFromBytes error: checksum error');
        }

        return id;
    }

    /**
     * idFromString
     * @param {*} s
     * @return {*}
    */
    static idFromString(s) {
        const bytes = base58_to_binary(s);
        return Id.idFromBytes(bytes);
    }

    static idFromInt(bigInt) {
        const b = Core.intToBytes(bigInt);
        return Id.idFromBytes(b);
    }
}
