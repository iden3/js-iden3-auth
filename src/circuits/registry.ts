import { AtomicQueryMTPV2PubSignalsVerifier } from '@lib/circuits/atomicMtpV2';
import { AtomicQuerySigV2PubSignalsVerifier } from '@lib/circuits/atomicSigV2';
import { Query } from '@lib/circuits/query';
import { Resolvers } from '@lib/state/resolver';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';
import { AtomicQueryV3PubSignalsVerifier } from '@lib/circuits/atomicV3';
import { BaseConfig, CircuitId, VerifiablePresentation } from '@0xpolygonid/js-sdk';
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
  new (pubSignals: string[], opts?: { [key: string]: unknown }): PubSignalsVerifier;
}

export type VerifierType = PubSignalsVerifier & PubSignals;

const supportedCircuits: {
  [key: string]: {
    verifier: PubSignals;
    opts?: { queryCount?: number; mtLevel?: number; mtLevelClaim?: number };
  };
} = {
  [CircuitId.AuthV2]: { verifier: AuthPubSignals },
  [CircuitId.AuthV3]: { verifier: AuthPubSignals },
  ['authV3-8-32']: { verifier: AuthPubSignals },
  [CircuitId.AtomicQueryMTPV2]: { verifier: AtomicQueryMTPV2PubSignalsVerifier },
  [CircuitId.AtomicQuerySigV2]: { verifier: AtomicQuerySigV2PubSignalsVerifier },
  [CircuitId.AtomicQueryV3]: { verifier: AtomicQueryV3PubSignalsVerifier },
  [CircuitId.AtomicQueryV3Stable]: { verifier: AtomicQueryV3PubSignalsVerifier },
  ['credentialAtomicQueryV3-16-16-64']: {
    verifier: AtomicQueryV3PubSignalsVerifier,
    opts: { mtLevel: 16, mtLevelClaim: 16 }
  },
  [CircuitId.LinkedMultiQuery10]: { verifier: LinkedMultiQueryVerifier },
  [CircuitId.LinkedMultiQuery10Stable]: { verifier: LinkedMultiQueryVerifier },
  ['linkedMultiQuery5']: {
    verifier: LinkedMultiQueryVerifier,
    opts: { queryCount: 5 }
  },
  ['linkedMultiQuery3']: {
    verifier: LinkedMultiQueryVerifier,
    opts: { queryCount: 3 }
  }
};

export class Circuits {
  static getCircuitPubSignals(id: string): {
    verifier: VerifierType;
    opts?: { queryCount?: number; mtLevel?: number; mtLevelClaim?: number };
  } {
    const circuit = supportedCircuits[id];
    if (!circuit) {
      throw new Error(`circuit ${id} is not supported`);
    }
    return {
      verifier: supportedCircuits[id].verifier as VerifierType,
      opts: supportedCircuits[id].opts
    };
  }
}
