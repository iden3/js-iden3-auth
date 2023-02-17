import { ISchemaLoader } from '@lib/loaders/schema';
import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { AtomicQueryMTPV2PubSignals } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignals } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';

export type VerifyOpts = {
  AcceptedStateTransitionDelay?: Date;
};

export interface PubSignalsVerifier {
  verifyQuery(
    query: Query,
    schemaLoader: ISchemaLoader,
    verifiablePresentation?: JSON,
  ): Promise<void>;
  verifyStates(resolver: Resolvers, opts?: VerifyOpts): Promise<void>;
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
