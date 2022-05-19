// Message is basic protocol message
export interface Message {
  type: string;
  data: unknown;
}

// AuthorizationRequestMessage is message that representes protocol authorization request
export interface AuthorizationRequestMessage {
  type: string;
  data: AuthorizationRequestBody;
}
// AuthorizationResponseMessage is message that representes protocol authorization response
export interface AuthorizationResponseMessage {
  type: string;
  data: AuthorizationResponseBody;
}

//AuthorizationRequestBody is body for AuthorizationRequestMessage
export interface AuthorizationRequestBody {
  audience?: string;
  callbackUrl?: string;
  scope: ZKPRequest[];
}

//AuthorizationRequestBody is body for AuthorizationResponseMessage
export interface AuthorizationResponseBody {
  scope: ZKPResponse[];
}

//CredentialFethcRequestBody is body for CredentialFetchRequestMessage
export interface CredentialFetchRequestBody {
  schema?: string;
  claim_id?: string;
}
// ProofData is a result of snarkJS groth16 proof generation
export interface ProofData {
  pi_a: string[];
  pi_b: string[][];
  pi_c: string[];
  protocol?: string;
  curve?: string;
}

// ZKPRequest is a request for zkp proof
export interface ZKPRequest {
  circuit_id: string;
  rules?: unknown;
}

// ZKPResponse is a response with a zkp
export interface ZKPResponse {
  circuit_id: string;
  pub_signals?: string[];
  proof_data?: ProofData;
}

// ProofMetadata is used for token
export class ProofMetadata {
  public additionalData: any;
  constructor(public authData: AuthenticationMetadata) {
    this.additionalData = {};
  }
}

// AuthenticationMetadata is auth data in user token
export interface AuthenticationMetadata {
  userIdentifier: string;
  userState: string;
  authenticationChallenge: number;
}
