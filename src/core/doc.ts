// IDEN3COMM_SERVICE_TYPE is service type for iden3comm protocol
export const IDEN3COMM_SERVICE_TYPE = 'iden3-communication';

// DEFAULT_CONTEXT_DID_DOCUMENT is default context for did documents
export const DEFAULT_CONTEXT_DID_DOCUMENT = 'https://www.w3.org/ns/did/v1';

// DID Documents
// https://w3c.github.io/did-core/#dfn-did-documents
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
