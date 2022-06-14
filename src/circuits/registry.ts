import { ISchemaLoader } from '@loaders/schema';
import { IStateResolver } from '@state/resolver';
import { AtomicQueryMTPPubSignals } from '@circuits/atomicMtp';
import { AtomicQuerySigPubSignals } from '@circuits/atomicSig';
import { AuthPubSignals } from '@circuits/auth';
import { Query } from '@circuits/query';

export interface PubSignalsVerifier {
  verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void>;
  verifyStates(resolver: IStateResolver): Promise<void>;
  verifyIdOwnership(sender: string, challenge: bigint): Promise<void>;
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
