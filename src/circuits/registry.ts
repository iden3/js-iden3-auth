import { ISchemaLoader } from 'loaders/schema';
import { IStateResolver } from 'state/resolver';
import { AtomicQueryMTPPubSignals } from './atomicMtp';
import { AtomicQuerySigPubSignals } from './atomicSig';
import { AuthPubSignals } from './auth';
import { Query } from './query';

export interface PubSignalsVerifier {
  verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void>;
  verifyStates(resolver: IStateResolver): Promise<void>;
}

export interface PubSignals {
  new (pubSignals: string[]): PubSignalsVerifier;
}

const auth = AuthPubSignals;
const credentialAtomicQueryMTP = AtomicQueryMTPPubSignals;
const credentialAtomicQuerySig = AtomicQuerySigPubSignals;

const supportedCircuits = {
  auth,
  credentialAtomicQueryMTP,
  credentialAtomicQuerySig,
};

export type VerifierType = PubSignalsVerifier & PubSignals;
export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    return supportedCircuits[id];
  }

  static registerCircuitPubSignals(id: string, circuit: VerifierType): void {
    supportedCircuits[id] = circuit;
  }
}
