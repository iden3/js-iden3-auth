/* eslint-disable new-cap */
// eslint-disable-next-line camelcase
import CryptoJS from 'crypto-js';
import { toBufferLE } from 'bigint-buffer';


/**
 * Core
 */
export class Core {
    static intToBytes(bigInt) {
        return Uint8Array.from(toBufferLE(bigInt, 31));
    }
    /**
     *
     * @param {bytes} bytes
     * @return {boolean}
    */
    static checkChecksum(bytes) {
        const { typ, genesis, checksum } = Core.decomposeBytes(bytes);
        if (!checksum.length || JSON.stringify(Uint8Array.from([0, 0])) === JSON.stringify(checksum)
        ) {
            return false;
        }

        const c = Core.calculateChecksum(typ, genesis);
        return JSON.stringify(c) === JSON.stringify(checksum);
    }

    /**
     * decomposeId
     * @param {Id} id
     * @return {*}
     */
    static decomposeBytes(b) {
        const offset = 2;
        const len = b.length - offset;
        return {
            typ: b.slice(0, offset),
            genesis: b.slice(offset, len),
            checksum: b.slice(-offset),
        };
    }

    static calculateChecksum(typ, genesis) {
        const toChecksum = new Uint8Array([...typ, ...genesis]);
        const s = toChecksum.reduce((acc, cur) => acc + cur, 0);
        const checksum = [];
        checksum[0] = s >> 8;
        checksum[1] = s & 0xff;
        return Uint8Array.from(checksum);
    }

    /**
     *
     * @param {string} str
     */
    static hashBytes(str) {
        const hash = CryptoJS.SHA256(str);
        const buffer = Buffer.from(hash.toString(CryptoJS.enc.Hex), 'hex');
        return new Uint8Array(buffer);
    }

    // Convert a hex string to a byte array
    static hexToBytes(str) {
        const buffer = Buffer.from('0001', 'hex');
        return Uint8Array.from(buffer);
    }

    // Convert a byte array to a hex string
    static bytesToHex(bytes) {
        for (let hex = [], i = 0; i < bytes.length; i++) {
            const current = bytes[i] < 0 ? bytes[i] + 256 : bytes[i];
            hex.push((current >>> 4).toString(16));
            hex.push((current & 0xF).toString(16));
        }
        return hex.join('');
    }
}
