import { ISchemaLoader } from 'loaders/schema';
import { IStateResolver } from 'state/resolver';
import { AtomicQueryMTPPubSignals } from './atomicMtp';
import { AuthPubSignals } from './auth';
import { Query } from './query';


export interface PubSignalsVerifier {
  verifyQuery(query: Query, schemaLoader: ISchemaLoader):Promise<void>;
  verifyStates(resolver:IStateResolver):Promise<void>;
}

export interface PubSignalsUnmarshaller {
  unmarshall(pubsignals: string[]):Promise<void>;
}

export type ICircuitPubSignals = PubSignalsVerifier & PubSignalsUnmarshaller;


const supportedCircuits: Record<string, ICircuitPubSignals> = {
  ["auth"]: new AuthPubSignals(),
  ["credentialAtomicMTP"]: new AtomicQueryMTPPubSignals(),
  ["credentialAtomicSig"]: new AtomicQueryMTPPubSignals(),
};

export class Circuits {

  static getCircuitPubSignals(id: string): ICircuitPubSignals {
    return supportedCircuits[id];
  }

  static registerCircuitPubSignals(id: string, circuit: ICircuitPubSignals): void {
    supportedCircuits[id] = circuit;
  }
}
