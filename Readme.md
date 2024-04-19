# js-iden3-auth

> Library for verification of authorization response messages of communication protocol in JWZ format
>

`npm i @iden3/js-iden3-auth --save`

### General description

The goal of iden3auth libraries is to handle authentication messages of communication protocol.

Currently, library implementation includes support of next message types

1. `https://iden3-communication.io/authorization/1.0/request`
2. `https://iden3-communication.io/authorization/1.0/response`

### RUN AND TEST

`npm run test`

**Temporal:**
For now to run jest tests without experimental feature support:

1. add mocked folder
<https://github.com/iden3/js-iden3-auth/tree/develop/__mocks__/%40digitalbazaar/http-client/dist/cjs>
2. change jest config.
<https://github.com/iden3/js-iden3-auth/blob/develop/jest.config.js>

---

Auth verification procedure:

1. JWZ token verification
2. Zero-knowledge proof verification of request proofs
3. Query request verification for atomic circuits
4. Verification of identity and issuer states for atomic circuits

### Zero-knowledge proof verification

> Groth16 proof are supported by auth library
>

Verification keys must be provided using `IKeyLoader` interface

### Query verification

Proof for each atomic circuit contains public signals that allow extracting user and issuer identifiers, states, signature challenges, etc.
Circuit public signals marshallers are defined inside library.To use custom circuit you need to register it with `registerCircuitPubSignals` function.

### Verification of user / issuer identity states

The blockchain verification algorithm is used

1. Gets state from the blockchain (address of id state contract and URL must be provided by the caller of the library):
   1. Empty state is returned - it means that identity state hasn’t been updated or updated state hasn’t been published. We need to compare id and state. If they are different it’s not a genesis state of identity then it’s not valid.
   2. The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough and we work with the latest user state.
   3. The non-empty state is returned and it’s not equal to the state that the user has provided. Gets the transition time of the state. The verification party can make a decision if it can accept this state based on that time frame.

2. Only latest states for user are valid. Any existing issuer state for claim issuance is valid.

### Verification of GIST

The blockchain verification algorithm is used

1. Get GIST from the blockchain (address of id state contract and URL must be provided by the caller of the library):
   1. A non-empty GIST is returned, equal to the GIST is provided by the user, it means the user is using the latest state.
   2. The non-empty GIST is returned and it’s not equal to the GIST is provided by a user. Gets the transition time of the GIST. The verification party can make a decision if it can accept this state based on that time frame.

## How to use

1. Import dependencies

    ``` javascript
    import {
        auth,
        resolver,
        protocol,
        loaders,
        circuits,
    } from 'js-iden3-auth';
    ```

2. Request generation:

    basic auth:

    ``` javascript
    const request = auth.createAuthorizationRequestWithMessage(
       'test flow', // reason 
       'message to sign', // message
       '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ', // sender 
      'http://example.com/callback?sessionId=1', // callback url
    );
    ```

    if you want request specific proof (example):

     ``` javascript
    const proofRequest: protocol.ZeroKnowledgeProofRequest = {
        id: 1,
        circuitId: 'credentialAtomicQueryMTPV2',
        query: {
          allowedIssuers: ['*'],
          type: 'KYCCountryOfResidenceCredential',
          context: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
          credentialSubject: {
            countryCode: {
              $nin: [840, 120, 340, 509],
            },
          },
      },
      };
      request.body.scope = [...scope, proofRequest];
    ```

3. Token verification

  Init Verifier:

  ``` javascript
  const ethStateResolver = new resolver.EthStateResolver(
    ethUrl,
    contractAddress,
  );

  const resolvers: resolver.Resolvers = {
    ['polygon:mumbai']: ethStateResolver,
  };

  const schemaLoader = getDocumentLoader({
    ipfsNodeURL: 'ipfs.io'
  });
  const ethStateResolver = new resolver.EthStateResolver('rpc url', 'contractAddress');
  const verifier = await auth.Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    }
  );
  ```

  FullVerify

  ``` javascript
  let authResponse: protocol.AuthorizationResponseMessage;
  authResponse = await verifier.fullVerify(tokenStr, authRequest);
  ```

 Verify manually or thread id is used a session id to match request

  ``` javascript
  const token = await verifier.verifyJWZ(tokenStr);
  authResponse = JSON.parse(
    token.getPayload(),
  ) as protocol.AuthorizationResponseMessage;
  const authRequest: protocol.AuthorizationRequestMessage; // get request from you session storage. You can use authResponse.thid field

  await verifier.verifyAuthResponse(authResponse, authRequest);
  ```

---

### Generate types for state contract

We can use [TypeChain](https://github.com/dethcrypto/TypeChain#readme) for generate TS types for a smart contract.

1. Install TypeChain;
2. Install @typechain/ethers-v5;
3. Run:

```bash
typechain --target ethers-v5 /path/to/state_contract.sol
```
## License

js-iden3-auth is part of the iden3 project copyright 2024 0kims association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
