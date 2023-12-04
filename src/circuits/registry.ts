import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import { AtomicQueryMTPV2PubSignalsVerifier } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignalsVerifier } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { DID } from '@iden3/js-iden3-core';
import { AtomicQueryV3PubSignalsVerifier } from './atomicV3';

export type VerifyOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
  // acceptedProofGenerationDelay is the period of time in milliseconds that a generated proof remains valid.
  acceptedProofGenerationDelay?: number;
  verifierDID?: DID;
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
const credentialAtomicQueryMTPV2 = AtomicQueryMTPV2PubSignalsVerifier;
const credentialAtomicQuerySigV2 = AtomicQuerySigV2PubSignalsVerifier;
const credentialAtomicQueryV3 = AtomicQueryV3PubSignalsVerifier;

export type VerifierType = PubSignalsVerifier & PubSignals;

const supportedCircuits: { [key: string]: unknown } = {
  authV2,
  credentialAtomicQueryMTPV2,
  credentialAtomicQuerySigV2,
  credentialAtomicQueryV3
};

export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    return supportedCircuits[id] as VerifierType;
  }
}
