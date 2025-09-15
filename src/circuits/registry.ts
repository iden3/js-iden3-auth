import { AtomicQueryMTPV2PubSignalsVerifier } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignalsVerifier } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { AtomicQueryV3PubSignalsVerifier } from '@lib/circuits/atomicV3';
import { BaseConfig, VerifiablePresentation } from '@0xpolygonid/js-sdk';
import { LinkedMultiQueryVerifier } from '@lib/circuits/linkedMultiQuery';
import { AuthPubSignals } from './auth';

export type VerifyOpts = {
  // acceptedStateTransitionDelay is the period of time in milliseconds that a revoked state remains valid.
  acceptedStateTransitionDelay?: number;
  // acceptedProofGenerationDelay is the period of time in milliseconds that a generated proof remains valid.
  acceptedProofGenerationDelay?: number;
  // allowExpiredMessages is a flag that allows the verification of expired messages.
  allowExpiredMessages?: boolean;
};

export interface PubSignalsVerifier {
  verifyQuery(
    query: Query,
    schemaLoader?: DocumentLoader,
    verifiablePresentation?: VerifiablePresentation,
    opts?: VerifyOpts,
    circuitParams?: { [key: string]: unknown }
  ): Promise<BaseConfig>;
  verifyStates(resolver: Resolvers, opts?: VerifyOpts): Promise<void>;
  verifyIdOwnership(sender: string, challenge: bigint): Promise<void>;
}

export interface PubSignals {
  new (pubSignals: string[]): PubSignalsVerifier;
}

const authV2 = AuthPubSignals;
const authV3 = AuthPubSignals;
const authV3_8_32 = AuthPubSignals;
const credentialAtomicQueryMTPV2 = AtomicQueryMTPV2PubSignalsVerifier;
const credentialAtomicQuerySigV2 = AtomicQuerySigV2PubSignalsVerifier;
const credentialAtomicQueryV3 = AtomicQueryV3PubSignalsVerifier;
const linkedMultiQuery10 = LinkedMultiQueryVerifier;

export type VerifierType = PubSignalsVerifier & PubSignals;

const supportedCircuits: { [key: string]: unknown } = {
  authV2,
  authV3,
  authV3_8_32,
  credentialAtomicQueryMTPV2,
  credentialAtomicQuerySigV2,
  credentialAtomicQueryV3,
  linkedMultiQuery10
};

export class Circuits {
  static getCircuitPubSignals(id: string): VerifierType {
    id = id.split('-')[0];
    return supportedCircuits[id] as VerifierType;
  }
}
