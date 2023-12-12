import { AuthorizationRequestMessage } from '@0xpolygonid/js-sdk';
import { Verifier } from '@lib/auth/auth';
import { resolvers, schemaLoader } from './mocks';
import path from 'path';
import { PROTOCOL_CONSTANTS } from '@0xpolygonid/js-sdk';

describe('Linked proofs verification', () => {
  it('should verification pass', async () => {
    const authRequest: AuthorizationRequestMessage = {
      id: '7b62b9a5-35ab-427d-a071-e5e1a46027eb',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '7b62b9a5-35ab-427d-a071-e5e1a46027eb',
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
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjAzODM0YTIxLTZiZGEtNGU2OC04NDZiLWY5N2U0NDBhYTk4ZSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3YjYyYjlhNS0zNWFiLTQyN2QtYTA3MS1lNWUxYTQ2MDI3ZWIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzIiwicHJvb2YiOnsicGlfYSI6WyIzMDM3NzQxNjk5MjQ3MzUxMjk5MjQwNjg2MDEwNjkwNzM0OTY4NzgxMjc2MDY5MTI5MzUzODAzNDgwNTE2NTU4ODAxODQxNjcwNTQ3IiwiMzk2MDExNDU5OTg3MDAxODIwNzc1Mzk3MjI2ODkxOTAwMjA0NTIxOTYyMDk5ODcwODMwMjE1ODgwMjYxNzIxNTAwMzY4MzMzMDE3MyIsIjEiXSwicGlfYiI6W1siMTY5NTQ5MTM1NjAzNDc0MDM2ODk0MzYyNzk1NzMxODk2NTI1OTIyMTIzMTI3Mjk2Mzc1ODI5NjUyMzA4OTQ1NzI3NjMwMjc3MjY2NTkiLCI1Mjc4NjM5NzkwMDQ2MjQ0NjU2ODU2MDAwNTIyNDQ4OTUwMDcxMjA4NzczNzc3ODAwMjkzMjk2NjI5MDQ1NjU3MzU4MTQwODg5Mjc3Il0sWyIxMjE2MDY3NzM3NTE0NTg3NjU4MDY0NTA4NDI5MjgzNjkwMTUzMTE4MzkwNzE0ODI4MTgwOTc3ODQ4MzM3MTQ5MjA3MDk3MTIzNDAxIiwiMTYxNzkzMDM1MzM5MDc5NDg5NTI4NDMwODA3ODU2NDk5NzU0OTU3MzkwODcwNjc2ODcxNDAxMDMyMjY4NzI0MjQ4NjMxNDk5ODUwMjgiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEwNDcyNjc0MTI2NTExODYwNDg2MzI1NjIxODMxMDM4OTcxNDI4MjYzMTI2OTY3NTIyMjg4MzU1NzUxMzExMzkzMTU1NTQxNDk5NDYiLCIxNTgwMzcwNDc5MDc3NzkwNjI0MTk1MTU3MjEzOTAxOTA5NzY2MjA0NzA4MzQxMTQ5NDg3MjAxOTczMDIzMDY4MTQwNTQyMzYwOTQ0MSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIwIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTk3NTQ4ODMyNDcyMDE3Mzk0MDE1MTQ0MjY5MTg0NDAwNTQxNzQ4ODY4NTk0MjA3NjczNTkyODY2ODE4OTQ5MDQ5NjY1NDQ3MTQ0MDciLCIwIiwiMCIsIjEiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDIzOTcxODQiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIxIiwiMCIsIjMiLCIxIiwiOTkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJsaW5rZWRNdWx0aVF1ZXJ5MyIsInByb29mIjp7InBpX2EiOlsiNTE5NTU0OTYyNjg5ODM1NjI1Mjc4MzU4NjExODE5MDg4MzEzNjE3NDYzMDg2Mzg1NjQ1MDgyMDM0MDY2NTQ5MDA1ODU4NzU4NzkwMyIsIjU1MjQwNzEzODIxNzQwNzA1MjEyNzE0MTQwMjA2MzMyNTA3OTU3ODM0NTE4NDY3MzM0NzMwMTk3NDU0MzczMzA3NjE5MTkzNzY4MDAiLCIxIl0sInBpX2IiOltbIjE4NjA5MjIzMzY0NDQ1ODExMjAwNzExMjUyMTMzNDM4OTQyOTUxODE2MzQyMzA4NTUwMjMyNzQyODA1NjQxNjc3NDk4NzMyMTU0NzUxIiwiMTk0NTc2NzY4NTAwNjA5OTk2NzIzNTU5NDgzMTE1MDA2ODAwMTk2MDg5MTU0MTczODQ1MjI2Njc4MzIxMDA1MDMyNTUwMjM2NTA3NjMiXSxbIjIwNDgyNzI2NjQyMjgwNzUwMjU1NTU1MjU0NTA2ODAwNzA2NjAxOTIxNjg1MjgyMzQ2NzY2MjcyNDE0NTQxNjgwOTE0MzI2MDc3MjQxIiwiMjAwNjc3Mzg3MjE1NzMxNzIyMTEzNjc3NTI5ODIwNzYwOTE4MDg4OTIyNzA1OTI2MDg2OTAzNDA2MDY1NDQyMjMxMzE2OTIxMjYxOSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjc0NTE3MDMzMjcxMjM2NDU1NzUwNjkwMDk4NDczOTg0MTg2NDA0MDE4OTU4ODQxMTE4ODAzMzI1ODUxMjAyOTQxNDAwNjM2OTA2OSIsIjEwMzI4NDU4NDg0NjQ5NTI3NDkwODg2NjA0MjM0NjIxMzk5MTI5MzQyMTY5NjY4OTE2MDQxMTM3Nzk3MzU3MDQ4MzUyNjcwNTkwNDMiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMTk3MzQ3MjkxODk2MTgxNTg5OTgyNTg4NTMzMDc4OTE4NjM1NTA4MDYwMDczODM0ODc0MjMxOTgxMDAzODM2ODI2MzM1MzI4NjYxNjIiLCIxIiwiMCIsIjAiLCIwIiwiMTAzNDE1NzQ0NDgzODY0ODUzMzgxMjYyMTI2OTQ3ODkyMjQ2NzYyNjE3OTgxNDAxMzIwNDY0OTYyMDQ3MzA0NDI3NDY3MDc3NDMzNTAiLCIxNDQ2MDc2Nzk5NTAyMDQ3ODA5MzUzMzE0MTYzMTE4MzA2MzgxMzIxOTg2OTU5MjQ0NzAzODM4MTUxMTg4MTIzMzc2MDYyMjIwODcyIiwiMzY0Mjc3Mzk0MDYwMTk3MjQwODY3Mjk5MzQ4MTQwNTYyODE2MTgyNzUxMTYyMjcwMTU4MDE0MjI0MjY5MTEyNzAyMTExOTgxMDU5NiJdfSx7ImlkIjozLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMyIsInByb29mIjp7InBpX2EiOlsiMjUzOTI5MzIzODAzNjI1NzAyMDkzNzgxMDI5MzMwNTQ0Mjk5OTIxOTA0ODg2NDQzNTA2NDk3NTcwOTk3MDcxMjI4OTMzNDM4MDk3NyIsIjEwODcyMDIyODY1MTUwNTg4NjE3MjUyNjYyNzEyNzcyNTc0MDIyNTY3NzA4MDI3NDc4NDUwMTE2NDAxMDE3NjMwMTYwMDUxMTIzNzExIiwiMSJdLCJwaV9iIjpbWyIxMjk5ODM0NTg0MjkwMzkxNDI4NTI1MjQ1ODEwMjM1MTkxMzc1OTU3OTIxNjY3NTA4ODk0NDc2MjAyNjQ5MjM5NDIyODQwMDA0Nzg0OCIsIjY0MjU1ODYyNDk0ODY1ODUzMTEyNzA4MzQzMDE3OTY5MjY3MzEyMDc2MTcyMjYwNjQ4MjM3NzIzMTcyMzU1MjExMzU4MTk5NjY4MzIiXSxbIjE0MjI5ODQ0NjIxMDc2NDg4ODg4NTM5MjM3MTQyNTc4MDk2NTI3ODk2Njg5Mzk4MzE0NTg5NTg2ODk3NTQwOTA2NjE0MDQ5MjQ2MDI1IiwiMTI5OTM0NTc2Mjg0ODUyMjM5ODc2OTgzMzA0MzExMzgxNTY5ODAwNjMzOTgyNzIyNDA5MjIwNjYyMDMyMDU4NTIwOTY2MzMxMTM1NDEiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE4NDMyNzExNTcyNTY4ODM4MzAxMDQxMTU3OTUwMDQxNjUwNTg3MjM1NjY3NTA5NzEzOTA4OTMwMjEzNTk4NDM4Mjc1NzQyNzA3MTEiLCI1NTkwMjM0MjE5NzcwMzE2OTQzNzQwNzk0NTU1NjAzMTYzNTM3OTYyODM2NjcxNDAwNTczMjM0OTg3MTk5NTg0ODUxMDA5ODAxMTQ2IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxOTczNDcyOTE4OTYxODE1ODk5ODI1ODg1MzMwNzg5MTg2MzU1MDgwNjAwNzM4MzQ4NzQyMzE5ODEwMDM4MzY4MjYzMzUzMjg2NjE2MiIsIjAiLCIwIiwiMSIsIjMiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwMjM5NzE5MSIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjAiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3dXc1dHlkWjdBQWQzZWZ3RXFQcHJucWppTkhSMjRqcXJ1U1BLbVYxViIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd6b2t2WjZrTW9vY0tKdVNiZnRkWnhURDZxdmF5R3BKYjNtNEZWWHRoIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjIxNTI0ODMyNDE1ODQzODgxMTQ5NTc1ODgyNzE4MjMxMzIzNDE0MDE3MDg1Mjc4MzA5MDY1NDE3MjEyMzY3MTgwMTg5OTE1MTE3NjA0IiwiOTYwNzY2NzcwMzQ1MDQ2MjIwNzIyMzg3MjQ2ODc1OTg2Njg1MzMyNzQwMTA0MDg4MTExODE2MTA3MjE0NTg4Mjg0MDE2NTQwMTg0NCIsIjEiXSwicGlfYiI6W1siMjAzNTk2MzU1MDI1NDYyNDc5ODkzNzkyMTMzMjY5MDc1NjEyNDYzODMyMTYwMzcyMzIzMDMzNjQzNTk4OTgyNzY5NDA1OTk0NTg0NzIiLCI4MTUyMjYzMDUyNDE1NzE0OTc1MjY2ODQ3MTk3MDY1ODczODc5MDY3MDgwOTg3ODU4NjM0NTQwNDAwNzQ1NzYyOTU4ODAzNzc1MTg2Il0sWyI1NjE1OTAzMjAwNTgzMjg4OTQxMTEyNjY3NDcwOTgwNTg0ODQyOTcwNTYyMzk0NzYwMDAwNTAwMTg1MTY4NDMzODI0MzQ0NDk3NDYwIiwiMTk2NTgzMDc0NTUzNTI4NjMyMjI2NjU5NDU4ODY0MDA3MDQ2OTQ1NTk1MzI5MTI0NDczNTgxMzMxMTU3OTM2OTc3OTIxNjU0MTI0OSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTYxNzExMzM2NTM1MTgxOTY3NTk3NzE5NzEyMTQ5OTI2NjMyMDE1NzU3MzI3Njg1OTQxMjQzNjUxMjQxNDgwMTA4MzcxMTE4MTc1NDYiLCIxMjg4ODgwMTgyMDgwNDg2NjEzMTE4OTAxOTY5MjM3NDY3MDEwMzM3MzUzMzc0MTMzMjM0NjE3MTQ3OTA3OTg4MDM4NzM0MzA4NzM4MyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ4MDk5MjE3MjgwMjM3NTYzMTcxOTkzMTcyMjAwNTQ0NzE5NTU4MDU4NDY5NTIwMTY4NjY0NzA4NDg3ODUwNDEzNTEyOTY2MTE5NTYiLCIwIl19';

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    verifier.fullVerify(tokenString, authRequest);
  });
});
