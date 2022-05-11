import { circuits } from './constants';

export class CircuitData {
  private verificationKey: unknown;
  constructor(
    private id: string,
    private description: string,
    verificationKey: string,
    private metadata: string,
  ) {
    this.verificationKey = JSON.parse(verificationKey);
  }

  getPublicSignalsSchema(): any {
    return this.metadata;
  }

  getVerificationKey(): any {
    return this.verificationKey;
  }
}

const supportedCircuits: Record<string, CircuitData> = {
  [circuits.authCircuitId]: new CircuitData(
    circuits.authCircuitId,
    'circuit for verification of  basic authentication',
    circuits.authenticationVerificationKey,
    circuits.authenticationPublicSignalsSchema,
  ),
  [circuits.atomicQueryMTPCircuitId]: new CircuitData(
    circuits.atomicQueryMTPCircuitId,
    'circuit for atomic query on standard iden3 credential',
    circuits.atomicQueryMTPVerificationKey,
    circuits.atomicQueryMTPPublicSignalsSchema,
  ),
  [circuits.atomicQuerySigCircuitId]: new CircuitData(
    circuits.atomicQuerySigCircuitId,
    'circuit for atomic query on standard iden3 credential',
    circuits.atomicQuerySigVerificationKey,
    circuits.atomicQuerySigPublicSignalsSchema,
  ),
};

export class Circuits {
  static getCircuit(id: string): CircuitData {
    return supportedCircuits[id];
  }

  static registerCircuit(id: string, circuit: CircuitData): void {
    supportedCircuits[id] = circuit;
  }
}
