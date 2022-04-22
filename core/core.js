// eslint-disable-next-line camelcase
import { base58_to_binary } from 'base58-js';

/**
 * Core
 */
export class Core {
    /**
         * idFromString
         * @param {*} s
         * @return {*}
        */
    static idFromString(s) {
        const bytes = base58_to_binary(s);
        return Core.iDFromBytes(bytes);
    }

    /**
       *
       * @param {*} b
       // eslint-disable-next-line valid-jsdoc
       *  @return {*}
       */
    static iDFromBytes(b) {
        const bytes = b ?? [];
        if (bytes.length !== 31) {
            throw new Error('IDFromBytes error: byte array incorrect length');
        }

        if (bytes.every((i) => i === 0)) {
            throw new Error('IDFromBytes error: byte array empty');
        }

        const id = [...bytes];

        if (!Core.checkChecksum(id)) {
            throw new Error('IDFromBytes error: checksum error');
        }

        return id;
    }

    /**
       *
       * @param {*} b
       * @return {*}
       */
    static checkChecksum(b) {
        const { typ, genesis, checksum = [] } = Core.decomposeId(id);

        if (!checksum.length || JSON.stringify([0, 0]) === JSON.stringify(checksum)) {
            return false;
        }

        const c = Core.calculateChecksum(typ, genesis);
        return JSON.stringify(c) === JSON.stringify(checksum);
    }

    /**
     * decomposeId
     * @param {*} id
     * @return {*}
     */
    static decomposeId(id) {
        const offset = 2;
        const len = id.length - offset;
        return {
            typ: id.slice(0, offset),
            genesis: id.slice(offset, len),
            checksum: id.slice(len, offset),
        };
    }

    static calculateChecksum(typ, genesis) {
        const toChecksum = new Uint16Array([...typ, ...genesis]);
        const s = toChecksum.reduce((acc, cur) => acc + cur, 0);
        const checksum = [];
        checksum[0] = s >> 8;
        checksum[1] = s & 0xff;
        return checksum;
    }
}
