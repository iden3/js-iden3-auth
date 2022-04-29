import { circuits } from './constants.js';

export class CircuitData {
    constructor(id, description, verificationKey, metadata) {
        this.id = id;
        this.description = description;
        this.verificationKey = (typeof verificationKey === 'string') ?
            JSON.parse(verificationKey) :
            verificationKey
        ;
        this.metadata = metadata;
    }

    getPublicSignalsSchema() {
        return this.metadata;
    }

    getVerificationKey() {
        return this.verificationKey;
    }
}

const supportedCircuits = {
    [circuits.authCircuitId]: new CircuitData(
        circuits.authCircuitId,
        'circuit for verification of  basic authentication',
        circuits.AuthenticationVerificationKey,
        circuits.authenticationPublicSignalsSchema,
    ),
    [circuits.atomicQueryMTPCircuitId]: new CircuitData(
        circuits.atomicQueryMTPCircuitId,
        'circuit for atomic query on standard iden3 credential',
        circuits.AtomicQueryMTPVerificationKey,
        circuits.atomicQueryMTPPublicSignalsSchema,
    ),
    [circuits.atomicQuerySigCircuitId]: new CircuitData(
        circuits.atomicQuerySigCircuitId,
        'circuit for atomic query on standard iden3 credential',
        circuits.AtomicQuerySigVerificationKey,
        circuits.atomicQuerySigPublicSignalsSchema,
    ),
    [circuits.KycBySignaturesCircuitID]: new CircuitData(
        circuits.KycBySignaturesCircuitID,
        'circuit for kyc claims verification',
        circuits.KycBySignaturesVerificationKey,
        circuits.KycBySignaturesPublicSignalsSchema,
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


