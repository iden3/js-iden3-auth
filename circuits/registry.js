import { circuits } from './constants.js';

export class CircuitData {
    constructor(id, description, verificationKey, metadata) { }

    GetPublicSignalsSchema() {
        return this.metadata;
    }
    GetVerificationKey() {
        return this.verificationKey;
    }
}

const supportedCircuits = {
    [circuits.AuthCircuitID]: new CircuitData(
        circuits.AuthCircuitID,
        'circuit for verification of  basic authentication',
        circuits.AuthenticationVerificationKey,
        circuits.AuthenticationPublicSignalsSchema,
    ),
    [circuits.AtomicQueryMTPCircuitID]: new CircuitData(
        circuits.AtomicQueryMTPCircuitID,
        'circuit for atomic query on standard iden3 credential',
        circuits.AtomicQueryMTPVerificationKey,
        circuits.AtomicQueryMTPPublicSignalsSchema,
    ),
    [circuits.AtomicQuerySigCircuitID]: new CircuitData(
        circuits.AtomicQuerySigCircuitID,
        'circuit for atomic query on standard iden3 credential',
        circuits.AtomicQuerySigVerificationKey,
        circuits.AtomicQuerySigPublicSignalsSchema,
    ),
};


export class Circuits {
    /**
     * Get Circuit
     * @param {string} id
     */
    static getCircuit(id) {
        return supportedCircuits[id];
    }
    /**
     * Register Circuits
     * @param {*} id
     * @param {*} circuit
     */
    static registerCircuit(id, circuit) {
        supportedCircuits[id] = circuit;
    }
}


