import { bytesToBase64url, hexToBytes } from '@0xpolygonid/js-sdk';

export const kycV2Schema = `{
    "@context": [
      {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "KYCAgeCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld#KYCAgeCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "serialization": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/serialization.md#",
            "birthday": {
              "@id": "kyc-vocab:birthday",
              "@type": "serialization:IndexDataSlotA"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "serialization:IndexDataSlotB"
            }
          }
        },
        "KYCCountryOfResidenceCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld#KYCCountryOfResidenceCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "serialization": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/serialization.md#",
            "countryCode": {
              "@id": "kyc-vocab:countryCode",
              "@type": "serialization:IndexDataSlotA"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "serialization:IndexDataSlotB"
            }
          }
        }
      }
    ]
  }`;

export const kycV3Schema = `{
    "@context": [
      {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "KYCAgeCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCAgeCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "birthday": {
              "@id": "kyc-vocab:birthday",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        },
        "KYCCountryOfResidenceCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld#KYCCountryOfResidenceCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "countryCode": {
              "@id": "kyc-vocab:countryCode",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        }
      }
    ]
  }`;

export const kycV4Schema = `{
    "@context": [
      {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "KYCAgeCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld#KYCAgeCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "birthday": {
              "@id": "kyc-vocab:birthday",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        },
        "KYCCountryOfResidenceCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld#KYCCountryOfResidenceCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "countryCode": {
              "@id": "kyc-vocab:countryCode",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        }
      }
    ]
  }`;

export const kycV101Schema = `{
    "@context": [
      {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "KYCAgeCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCAgeCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "birthday": {
              "@id": "kyc-vocab:birthday",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        },
        "KYCCountryOfResidenceCredential": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCCountryOfResidenceCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "countryCode": {
              "@id": "kyc-vocab:countryCode",
              "@type": "xsd:integer"
            },
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            }
          }
        },
        "KYCEmployee": {
          "@id": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld#KYCEmployee",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "kyc-vocab": "https://github.com/iden3/claim-schema-vocab/blob/main/credentials/kyc.md#",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
            "documentType": {
              "@id": "kyc-vocab:documentType",
              "@type": "xsd:integer"
            },
            "ZKPexperiance": {
              "@id": "kyc-vocab:hasZKPexperiance",
              "@type": "xsd:boolean"
            },
            "hireDate": {
              "@id": "kyc-vocab:hireDate",
              "@type": "xsd:dateTime"
            },
            "position": {
              "@id": "kyc-vocab:position",
              "@type": "xsd:string"
            },
            "salary": {
              "@id": "kyc-vocab:salary",
              "@type": "xsd:double"
            }
          }
        }
      }
    ]
  }`;

export const exampleDidDoc = `{"@context":["https://www.w3.org/ns/did/v1",{"EcdsaSecp256k1RecoveryMethod2020":"https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020","blockchainAccountId":"https://w3id.org/security#blockchainAccountId"}],"id":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65","verificationMethod":[{"id":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020","type":"EcdsaSecp256k1RecoveryMethod2020","controller":"did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65","blockchainAccountId":"eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65"}],"authentication":["did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"],"assertionMethod":["did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020"]}`;
