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

// ContractInvokeRequestMessage is struct the represents iden3message contract invoke request
export interface ContractInvokeRequestMessage {
  id: string;
  typ: string;
  type: string;
  thid: string;
  body: ContractInvokeRequestMessageBody;
  from: string;
  to?: string;
}

// ContractInvokeRequestMessageBody is body for ContractInvokeRequestMessage
export interface ContractInvokeRequestMessageBody {
  message?: string;
  reason: string;
  transaction_data: TransactionData;
  scope: ZKPRequest[];
  did_doc?: DIDDocument;
}

// TransactionData is data for on-chain verification
export interface TransactionData {
  contract_address: string;
  method_id: string;
  chain_id: number;
  network: string;
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
  circuitId: string;
  optional?: boolean;
  query: unknown;
}

// ZKPResponse is a response with a zkp
export interface ZKPResponse {
  id: number;
  circuitId: string; // `circuitId` compatibility with golang implementation.
  verifiablePresentation?: JSON;
  pub_signals: string[];
  proof: ProofData;
}

export type DIDDocument = {
  '@context': string | string[];
  id: string;
  service?: Service[];
};
// Service describes did services
export type Service = {
  id: string;
  type: string;
  serviceEndpoint: string;
};
