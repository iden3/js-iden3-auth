import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { AtomicQueryMTPV2PubSignals } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignals } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader, Options } from '@iden3/js-jsonld-merklization';

export type VerifyOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
};

export interface PubSignalsVerifier {
  verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
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
