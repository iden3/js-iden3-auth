import { DIDDocument } from '@lib/core/doc';

// Message is basic protocol message
export interface Message {
  id: string;
  typ: string;
  thid: string;
  type: string;
  body: unknown;
}

// AuthorizationRequestMessage is message that represents protocol authorization request
export interface AuthorizationRequestMessage {
  id: string;
  typ: string;
  type: string;
  thid: string;
  body: AuthorizationRequestBody;
  from: string;
  to?: string;
}
// AuthorizationResponseMessage is message that representes protocol authorization response
export interface AuthorizationResponseMessage {
  id: string;
  typ: string;
  type: string;
  thid: string;
  body: AuthorizationResponseBody;
  from: string;
  to: string;
}

//AuthorizationRequestBody is body for AuthorizationRequestMessage
export interface AuthorizationRequestBody {
  message?: string;
  reason: string;
  callbackUrl: string;
  scope: ZKPRequest[];
  did_doc?: DIDDocument;
}

//AuthorizationRequestBody is body for AuthorizationResponseMessage
export interface AuthorizationResponseBody {
  message?: string;
  scope: ZKPResponse[];
  did_doc?: DIDDocument;
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
  id: number;
  circuit_id: string;
  optional?: boolean;
  rules: unknown;
}

// ZKPResponse is a response with a zkp
export interface ZKPResponse {
  id: number;
  circuit_id: string;
  pub_signals: string[];
  proof: ProofData;
}

// Schema is a protocol schema
export interface Schema {
  hash?: string;
  url: string;
  type: string;
}
