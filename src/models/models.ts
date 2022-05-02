export interface Message {
  type: string;
  circuit_id?: string;
  data: MessageDataData;
}

export interface MessageDataData {
  schema?: string;
  claim_id?: string;
  scope: Scope[];
  audience?: string;
  callbackURL?: string;
}

export interface ProofData {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

export interface Scope {
  circuit_id: string;
  type: string;
  rules?: unknown;
  pub_signals?: string[];
  proof_data?: ProofData;
}

// export interface ProofMetadata {
//   authData: {
//     authenticationChallenge: number;
//     userIdentifier: string;
//     userState: string;
//   };
//   additionalData: any;
// }

export class ProofMetadata {
  public additionalData: any;
  constructor(public authData: AuthenticationMetadata) {
    this.additionalData = {};
  }
}

export interface AuthenticationMetadata {
  userIdentifier: string;
  userState: string;
  authenticationChallenge: number;
}
