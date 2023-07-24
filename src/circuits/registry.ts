import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { AuthAtomicQueryMTPV2PubSignals } from '@lib/circuits/atomicMtpV2';
import { AuthAtomicQuerySigV2PubSignals } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';

export type VerifyOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
  // acceptedProofGenerationDelay is the period of time in milliseconds that a generated proof remains valid.
  acceptedProofGenerationDelay?: number;
};

export interface PubSignalsVerifier {
  verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: JSON,
    opts?: VerifyOpts
  ): Promise<void>;
  verifyStates(resolver: Resolvers, opts?: VerifyOpts): Promise<void>;
  verifyIdOwnership(sender: string, challenge: bigint): Promise<void>;
}

export interface PubSignals {
  new (pubSignals: string[]): PubSignalsVerifier;
}

const authV2 = AuthPubSignalsV2;
const credentialAtomicQueryMTPV2 = AuthAtomicQueryMTPV2PubSignals;
const credentialAtomicQuerySigV2 = AuthAtomicQuerySigV2PubSignals;

const supportedCircuits = {
  authV2,
  credentialAtomicQueryMTPV2,
  credentialAtomicQuerySigV2
};

export type VerifierType = PubSignalsVerifier & PubSignals;
export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    return supportedCircuits[id];
  }
}
