import { ISchemaLoader } from '@lib/loaders/schema';
import { IStateResolver } from '@lib/state/resolver';
import { AtomicQueryMTPPubSignals } from '@lib/circuits/atomicMtp';
import { AtomicQuerySigPubSignals } from '@lib/circuits/atomicSig';
import { AuthPubSignals } from '@lib/circuits/auth';
import { Query } from '@lib/circuits/query';

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
