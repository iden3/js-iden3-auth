import { AuthorizationRequestMessage } from '@0xpolygonid/js-sdk';
import { Verifier } from '@lib/auth/auth';
import { resolvers, schemaLoader } from './mocks';
import path from 'path';
import { PROTOCOL_CONSTANTS } from '@0xpolygonid/js-sdk';

describe('Linked proofs verification', () => {
  it('should verification pass', async () => {
    const authRequest: AuthorizationRequestMessage = {
      id: 'f5bcdfc9-3819-4052-ad97-c059119e563c',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: 'f5bcdfc9-3819-4052-ad97-c059119e563c',
      body: {
        callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
        reason: 'reason',
        message: 'mesage',
        did_doc: {},
        scope: [
          {
            id: 1,
            circuitId: 'credentialAtomicQueryV3',
            optional: false,
            query: {
              proofType: 'BJJSignature2021',
              allowedIssuers: ['*'],
              type: 'KYCAgeCredential',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: {
                documentType: {
                  $eq: 99
                }
              }
            }
          },
          {
            id: 2,
            circuitId: 'linkedMultiQuery3',
            optional: false,
            query: {
              groupId: 1,
              proofType: 'Iden3SparseMerkleTreeProof',
              allowedIssuers: ['*'],
              type: 'KYCEmployee',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: {
                documentType: {
                  $eq: 1
                },
                position: {
                  $eq: 'boss',
                  $ne: 'employee'
                }
              }
            }
          },
          {
            id: 3,
            circuitId: 'credentialAtomicQueryV3',
            optional: false,
            query: {
              groupId: 1,
              proofType: 'BJJSignature2021',
              allowedIssuers: ['*'],
              type: 'KYCEmployee',
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: {
                hireDate: {
                  $eq: '2023-12-11'
                }
              }
            }
          }
        ]
      },
      from: 'did:iden3:polygon:mumbai:wzokvZ6kMoocKJuSbftdZxTD6qvayGpJb3m4FVXth'
    };

    const tokenString =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjkzMTA1YWY0LTlhMjYtNDE4NS1iYzg5LTVjYzdlMzJhMTVlYSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmNWJjZGZjOS0zODE5LTQwNTItYWQ5Ny1jMDU5MTE5ZTU2M2MiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzIiwicHJvb2YiOnsicGlfYSI6WyIyMzc3ODYxNzM3MTczNjg3MTQ0MDg4NDk5ODkxNzU5Nzk1MTY2MjEyNjQ0MjQyODEwMTIyNTAzOTkwOTYwNTg1OTM1OTg2MDU2NTA0IiwiOTA1Mjg4MzI4MjA3MDg1NDU0NzE2MTM5NzQwMzU2MjQ0ODAzMTI0NDMzOTM3MDY5MDM0NTA3NzA4MTE1Njk3MzU2MTI0NTE1NjY3MSIsIjEiXSwicGlfYiI6W1siMTM5Njk4NDkwMTc1MDk1MTUzMzcxMDIzNDQ1NTk5NDcxODc5MjY5MzU4MDY2ODQyNDEzNzM5NDAwMTc3Mjc5ODE1ODIxNTMyMDcyNTYiLCI1MTk1NDM1MzQxODk1MzkzMDQ0Nzk5NDY3ODc0NDE0MzI3Njc4ODU3MzQyMjU0NDkwMzQ0NjkwMjk3NDcwMzMzNDcyNzI1MTI1NTM3Il0sWyIxNDc5MjM1NjY2Njg4MTU4NTExOTkwNzQzNDk4MjYwOTkxNDIxNjkyMDYxODYyMDMxMTQ2MDQwOTEyNTQ4MjIwNzk3NTQwNjk1NjAzMCIsIjE5NzQ3OTc5MDY0MTcyODAyOTMxMjUyMzg4ODg2OTczOTk0NzQ2OTk2NjM1NDgzMzg4MDM3MzkzMzMzMTA2NzA3MjQ1NjQwNTExMDE4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNzYzOTg2NTQwMjU5MTMwNDM4Njc1MDUyMzIwNDE3OTcyMzY3MDQ0NjkyNjY4Njg3NzgyNjA5OTgxMDM2Mjk1MTQ0NDY0OTkzNjI1NiIsIjE2NzM3Nzc2MDY3Mzk0NTc3MDc1NDYxMjAxNTk3NTc0OTM5NTk0MTA3MTg5Mjk2MDYxNTc0NzgxNDk4MzU3MjE3MjI1MjYzNjM0NDY4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIwIiwiMCIsIjAiLCIxIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzAyNjM0MTUzIiwiMTk4Mjg1NzI2NTEwNjg4MjAwMzM1MjA3MjczODM2MTIzMzM4Njk5IiwiMSIsIjAiLCIzIiwiMSIsIjk5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX0seyJpZCI6MiwiY2lyY3VpdElkIjoibGlua2VkTXVsdGlRdWVyeTMiLCJwcm9vZiI6eyJwaV9hIjpbIjE2MzE3Mjg5MzAzMDI4NTgwMDA3NzMwOTY1MDE2NTk5NDU5MjQ2OTA5NDg4Mzg1MDkzNjU2NDYwMTk4Mjk0MTc1Njc1NDg3ODUzNDEzIiwiMTkzNTE4OTE0OTc3MTg2NTc4MTIwMDIzNzc4ODQ5NjkxNTYxNDk3NDQ2MjQwNzI1NzU1MzM0MTAyNzA1MjQ3ODI2Nzc5ODc2MDA4MTYiLCIxIl0sInBpX2IiOltbIjIwMzg1MzQ5Mjk3MTE1NTI1Njc1Mzc3MDI5ODA1NjgwMDI5ODQzODU2NDYyMTQzMzM4MTg1ODE3MDY0MDE5NzM5Njk5Mjc5NDIxMzMxIiwiMTU3NzU3NDk2MjEzNTI5MzkyODUyMDI5NzY1MDgwNzM3NTY3NjQ0NzMxNjgwMDMxMDExNzgxMjU0NTg1MDIzMTU3MjUwMTQxNDIxMTQiXSxbIjI4MjgxMDEwNjY0NjYwNDY1NzQwODY4NDUyMjUwNTI1NDQwNjk0MzAzMjYwNDkxODUzMTc5MDAyNTk5ODAxNDg3OTgzMDU3MzQ5MzgiLCIxNzQzOTE3MzM1ODI3MjMxNjUxODQyMjExNTgzMjU1ODk2OTEzNTEwNjkyMzEzMDg4ODcwNDgxMzQ5NTIxMDc2ODc1MDYxNTM3MjI0MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTQyMDU4Nzc3NzIyMzE5OTcyMzcxNjkyMjEzNTExMjQxMjM5Nzc4NzUxODk3NzEzMjg1MTA1Njc3NDY5MDQwNTk3MDE4NDU0MTk5MjQiLCI2ODYzNDE3NDgyMzM0NTE2NzEyNDk4MzI0Mzc2NTUxOTUzODI0OTUxODIyODQ5NzkyNDM2OTk5ODgzNzE5MDg1NzIzMTYwMDgwMTE2IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEzODU1MjgyNzU2MDg5MjI2NTcyMjY5MDk1ODYxNzA0MjgyNzM1NjgxMzU1MDYxNjc4MjgyOTE5NDgwNTEzMDcwNzczNTQwNzI1MDgwIiwiMSIsIjAiLCIwIiwiMCIsIjEwMzQxNTc0NDQ4Mzg2NDg1MzM4MTI2MjEyNjk0Nzg5MjI0Njc2MjYxNzk4MTQwMTMyMDQ2NDk2MjA0NzMwNDQyNzQ2NzA3NzQzMzUwIiwiMTQ0NjA3Njc5OTUwMjA0NzgwOTM1MzMxNDE2MzExODMwNjM4MTMyMTk4Njk1OTI0NDcwMzgzODE1MTE4ODEyMzM3NjA2MjIyMDg3MiIsIjM2NDI3NzM5NDA2MDE5NzI0MDg2NzI5OTM0ODE0MDU2MjgxNjE4Mjc1MTE2MjI3MDE1ODAxNDIyNDI2OTExMjcwMjExMTk4MTA1OTYiLCIxIiwiMSIsIjEiXX0seyJpZCI6MywiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMiLCJwcm9vZiI6eyJwaV9hIjpbIjE5MzcxNzAxNTk2MDc3MzY1MzkwMDQzNzk5MTYxOTIzNzc0Mzk4ODEyOTI0NTcwNTQ2MjU5NzU2NDY2MzUwODg5NzAzMTgzMjU5Mzk4IiwiODcxODAyNDAyNDU5ODE0NTUzMDY3Mzg0Mjk0MTc0OTczODIxOTQyMjc0NjI2MzUxNjYyMDg3MjAyMDQ4MDMyMzg0ODg3OTIzNTk5OSIsIjEiXSwicGlfYiI6W1siMTc1Mzg0MTgxNjA5MjQ1MzY2OTI5NDA0MjYyMzgxNTI3NzI3ODA0NzIzMTEzNTI0NDI0MDkzOTg3MDc4Mzk5NjQxOTAyODY4MjMyNjkiLCIxNzczMjgyNzQ3MjY3NjE4NjM5NzUxNDA1NjM5OTg2OTU1ODE0Njk4NDk2ODczNTc2NTM4NDI4Mjk2OTcxNTI3NDY3MTgyOTc1NzMzMiJdLFsiMTExNzU1NjA3NDgwMjMyNzk5NjY3MDM2MDc2OTE5ODQxNzkxOTEzMjY1NTUzNDMyMzQ5MTk1Mjg0MDkxMTY5OTI2NTgzODQ5NTk0MzIiLCIyNzE5Njk2MTUzNzc3MjEyODEwMjI2ODIzMjI1NTg4MTY4ODU2MjEyODY4NjMwNzk0NzkxNTkzNjk1MDU3NjQzMDcwNDU4NDg0MTMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NDIyOTY4MDkzOTY5MTc5NzAwMTYyNDQ4ODkzOTE4Nzk3NDQxMDUwODg1NzMyOTIwMzk3NTExMjM4MDA1OTM3NTI3MzkyOTczODk3IiwiOTIyNzU1NDU4NDExOTM4NTk3NTUzMjUzMTIzNzE3NDY1MzQ1MDE3NjAzNzQyNjI3MjUxNTcyOTk2NDIyNTIyNjgwMzY0MTA2NzMyIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxMzg1NTI4Mjc1NjA4OTIyNjU3MjI2OTA5NTg2MTcwNDI4MjczNTY4MTM1NTA2MTY3ODI4MjkxOTQ4MDUxMzA3MDc3MzU0MDcyNTA4MCIsIjAiLCIwIiwiMSIsIjMiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwMjYzNDE1OSIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjAiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3dXc1dHlkWjdBQWQzZWZ3RXFQcHJucWppTkhSMjRqcXJ1U1BLbVYxViIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd6b2t2WjZrTW9vY0tKdVNiZnRkWnhURDZxdmF5R3BKYjNtNEZWWHRoIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNjU0NjI5MjU5MDg0NzYxNzUyODQ5NDg0NDMyMTEyMDc0NjE4MjMyNzg3ODUzNDkyNjIyMzc4Njk0NDE2MjUyNjM2OTY2MTI3MTYzIiwiMTQxNDIwMzg4NjU0NDE2NDk1Njc3ODI4Nzc4NTcyMDg2NzYwNjkxOTU4MTQ3MjMzODYxMTI4MTM0MTM1OTI0NTEzMTUxMzA3OTU2MjYiLCIxIl0sInBpX2IiOltbIjg0ODQwNjUyNzc4NDA5Mjg1Njk0MTg1MDEyNTUyNTMzMTAxMTcxOTkyMDk1MDc0MzUxMTEzMTg0NDIzNjY3NTI3NzUyMTk3MTA3MiIsIjE4ODYwMzYwNTMxNDg2NzI0MDQ5NzE4NzIzMTc0NTc3ODQ5MDUwNjAwOTM5MTg2NzEwMTkwNDYxNDk2MTUxMDk0Nzc3NTM1NjMwNjQ5Il0sWyIxMjM4ODk4MTYwNDM5ODg0ODcwMjk0MDkxMjc2MzU0MTQ1NDI3MTk2MDQzMzc3ODQ5OTIzNTg5OTU5NDgyODUxOTQzODI5OTE2MjMxOCIsIjE5NzM0Nzg1NTI1MjcwNjcxNTA4MDU5MzA2NTI5NjkwNjI5Mjk5NDQ2NTQ1MzUzNDczOTI1MTIzMzQzNjg3OTk1MDQwMzM4NTY3NDQ3Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNDM5NDAzNTg2Njk3NzE1Nzg2MjY0MTI1NDg0NzY1MzYwMjUwOTAzNzk5MTk1MDk3ODc4MjEzMTA0MDI5MzQ3MjI1MjU5OTcyMDU2NCIsIjM3MjY4OTU2ODIzMjE1ODU4Nzg1NTkwMjkxMTc3MzUwODMyNTQ2NjI4MzY1MjI1OTkxNDExOTgyMDIwNDc0NDQ3NjUxNTQxMjcyOTAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCIxMjk1MzgzMzc0NzM4ODkwNDU2OTQ5MTMwMDc1MDE1ODU1NDcwMTk4NzIyMDAxMDYwOTYzNDczMjM0NTEzNDM3MjY5Mzg5NDMzNzk5MCIsIjAiXX0';

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    verifier.fullVerify(tokenString, authRequest);
  });
});
