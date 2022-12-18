import { ISchemaLoader } from '@lib/loaders/schema';
import { IStateResolver } from '@lib/state/resolver';
import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { AtomicQueryMTPV2PubSignals } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignals } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';

export interface PubSignalsVerifier {
  verifyQuery(query: Query, schemaLoader: ISchemaLoader): Promise<void>;
  verifyStates(resolver: IStateResolver): Promise<void>;
  verifyIdOwnership(sender: string, challenge: bigint): Promise<void>;
}

export interface PubSignals {
  new (pubSignals: string[]): PubSignalsVerifier;
}

const authV2 = AuthPubSignalsV2;
const credentialAtomicQueryMTPV2 = AtomicQueryMTPV2PubSignals;
const credentialAtomicQuerySigV2 = AtomicQuerySigV2PubSignals;

const supportedCircuits = {
  authV2,
  credentialAtomicQueryMTPV2,
  credentialAtomicQuerySigV2,
};

export type VerifierType = PubSignalsVerifier & PubSignals;
export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    return supportedCircuits[id];
  }
}
