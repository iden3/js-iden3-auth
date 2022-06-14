import { ISchemaLoader } from '@app/loaders/schema';
import { IStateResolver } from '@app/state/resolver';
import { AtomicQueryMTPPubSignals } from '@app/circuits/atomicMtp';
import { AtomicQuerySigPubSignals } from '@app/circuits/atomicSig';
import { AuthPubSignals } from '@app/circuits/auth';
import { Query } from '@app/circuits/query';

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
