import {
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  CircuitId,
  IDataStorage,
  IdentityWallet,
  CredentialWallet,
  ProofService,
  CredentialStatusResolverRegistry,
  IPackageManager,
  CredentialStatusType,
  RHSResolver,
  FSCircuitStorage
} from '@0xpolygonid/js-sdk';
import { Verifier } from '@lib/auth/auth';
import {
  getInMemoryDataStorage,
  getPackageMgr,
  MOCK_STATE_STORAGE,
  registerBJJIntoInMemoryKMS,
  resolvers,
  schemaLoader,
  testOpts
} from './mocks';
import path from 'path';

describe('Linked proofs verification', () => {
  let packageMgr: IPackageManager;
  let dataStorage: IDataStorage;
  let idWallet: IdentityWallet;
  let credWallet: CredentialWallet;
  let proofService: ProofService;

  beforeEach(async () => {
    const kms = registerBJJIntoInMemoryKMS();
    dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
    const circuitStorage = new FSCircuitStorage({
      dirname: path.join(__dirname, './testdata')
    });

    const resolvers = new CredentialStatusResolverRegistry();
    resolvers.register(
      CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      new RHSResolver(dataStorage.states)
    );

    credWallet = new CredentialWallet(dataStorage, resolvers);
    idWallet = new IdentityWallet(kms, dataStorage, credWallet);

    proofService = new ProofService(idWallet, credWallet, circuitStorage, MOCK_STATE_STORAGE, {
      documentLoader: schemaLoader
    });

    packageMgr = await getPackageMgr(
      await circuitStorage.loadCircuitData(CircuitId.AuthV2),
      proofService.generateAuthV2Inputs.bind(proofService),
      () => Promise.resolve(true)
    );
  });

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
            circuitId: CircuitId.AtomicQueryV3,
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
            circuitId: CircuitId.LinkedMultiQuery10,
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
            circuitId: CircuitId.AtomicQueryV3,
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
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjNhNTQ1YjY5LTYyZDctNGU2Yy05MWI0LTYyNzk4ZmI1NWYzZCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmNWJjZGZjOS0zODE5LTQwNTItYWQ5Ny1jMDU5MTE5ZTU2M2MiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTkyMjQ3MjAxNDIyMDUxMjkxMzM3MjA1MDg4ODY1NDQ2NDI3NDczNTEyOTg3OTczOTA5NzUzMTAwNTMxMTE1ODE0MzczMTg2MjY1NDciLCIxMjM4MzUxMjM5OTAzMDU3NDM3MzE1OTU4MjkwODU5Mjk0MDUyNjM0MTUyOTg2OTY5NDE2ODQ4MzQzNjkxMzc0NTU2MDIyNDYwODExNSIsIjEiXSwicGlfYiI6W1siNTMyMDA4NjUyMjA3ODEzMTE1ODM4MDI0NTMzODM4NzE5NTkxMjAwNzI1MjM5OTE4NzI0NjgwNjk2NDExNTQzMDA3MDkyODc5MDc1MSIsIjEzMTg1MzQ3Mzk3MDUxOTg3NTMzMDg1MzE0MjY1NjcxNDc0OTc2NTExODUyMDI4OTg5Njg5NDA1NTM1NDA2NTE0NTc0MTAyNTAwMDkyIl0sWyIxNTkyNjU1NTM5MDYwMTg3MDUyNTQzNjcwMDU1NDgwNTgwNjI2MTIyNDk1MzM0Mzg5MzUwMjgzNjY0OTY1MTg4NzcxODUyMjY0NDA0MSIsIjE3NTI2MzY3NzU4MTUwODcwMzYxOTcxMzgzNzU5NDIzODg3MTYwNDgzNTYwOTg0NDk2MTc4OTkzNzAwODI3MTEzOTcxNDE0ODY1OTM5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNTYzNTU1MjQ2MTQ1MzM4NDQxODA1OTg1NTk5ODc0NDc3NDk3MDA0NDA5NjcwOTU3NTYxODQ2MjkyNTI5ODI4OTA2NTQ2NjkzMzc3MiIsIjE3Nzc0MjA3NDQyNTU1NzUwNDU0NTg3NDU2MjgwMzg0NDA1NDU1NDkwMzY1NDQ4ODQ1MTIxNzQ5MjY3MDM2ODU3NzMwNTM1NzkyMjE4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIwIiwiMCIsIjAiLCIxIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzA5NzE3NzI2IiwiMTk4Mjg1NzI2NTEwNjg4MjAwMzM1MjA3MjczODM2MTIzMzM4Njk5IiwiMCIsIjMiLCIxIiwiOTkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIwIl19LHsiaWQiOjIsImNpcmN1aXRJZCI6ImxpbmtlZE11bHRpUXVlcnkxMC1iZXRhLjEiLCJwcm9vZiI6eyJwaV9hIjpbIjEyNTQwOTIwMzkxMzEzMTg2NjE2NzQwNTkwNjQxODUxNjk0NzM0NDU1MDkwNDkwMzA4MjI3MDQ2OTg4NTUzMTMxMTU4NjY0MzE5NTA1IiwiNDM5OTEyNDUwNTc5MzYxOTYzODc1MzQyOTcxMjk5NzEzOTczMzkxNzIzNjMxNzgwNDk2MDkyMzU5NTg3NzkzMDY3ODE3MjM4MDk3OCIsIjEiXSwicGlfYiI6W1siNTY4NDA4Njg4Nzc3MDk0NzYzODEzODAxMTcyNDYzMTk5MTYzNzg1MDUwNjI1NzE1MTEyNTU1MDc2Mjk1NDg3NzUzNDQ0NTI3MDMzNiIsIjE4MDA0MDk5MjM5MzQxODEyMDgxMzY1NzIyNzc3NzA2ODc0Mjg5OTI0NDgxNjQ4OTQ0ODcxNjIwMDcyNTI3NTIyMjkxNzE3MzQyMDYzIl0sWyIyMDA0NzA1Mzc0Mjg0ODA3MzQwOTM4NjM2MzgzNjkzNTk4NTA4ODY4MDU4MTk0Mjg3MDE1Mzc0MzM5MTQxNzA1NjIwMDg0Njg3NDkyNyIsIjE5ODI4NzczNTMzODUwNDM0ODEyNTA2OTQ5MDkyNDg2MDg4MzU0NDM5MDczODMwMzIwODM1MzYyNTUwMTM4Nzc1OTY0MjkzMTM1OTg4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIzMDE2MTQ4NzUwODgwNDIwNTE1OTYxMTMzMDQzODIwOTgwMzM4Mzc2NDk1NjI0NjQ0NjY3NTMwODc4MTI5MzAzNjkzNDk0Mjc5MzEyIiwiMTAwNzYzNDQxNTA1NzcxNzg3MjIyODkyMzg0MDE0MjE0NzQ4NjY5NTQ0Mzc1NjUwMzcyMzAzOTE1MzAwMzExMTkwOTMxMjU2NzU4NzAiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjEwMzU0NjMyNjY5MzE0MTUzNjkzNTIyMTQyMTY2MDkxMTgyOTU3Mzg4MjcyMDc0MDU5NDQ0MjM1MTA4MjAxMTIxNDcxNjExMTYzMDMiLCIxIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjE1NTc3MTE0Nzk5MDU2OTM5NjMzNTUyODQ1NTMxMDExMDI0NjcyOTM5NDkzNDkyNzY5NjI4Mjg1NjYxMzU5NzExNjU1MjE0NTYxMTYyIiwiMTY5OTg3NjI5NjUzOTY5NDQ3ODI2Njc1NTc3NDExODU4MjgxMzY0Njc3NDc3NjI4MzAwMjgyMTcwMjc5NzM2MTczNzM4NjIzMDE5NTgiLCI5MzAyNTI2MjA4NTA3NzUzNzk5NTAxMTMwMTI4OTA4NDk0NjczNDEyNDQzNjMxNTQxNDI0NDA5NTUxMjA1Mjc3NTI5OTQ5NjYyMzk0IiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiLCIxNDYxMjUxODAwNjQ5Mzk5ODAzNzE0OTI5OTY0Nzk3NDIzNzc3MTU1MTA3MDMxMjA5Njg4MjQwNzQ0MDY1MTA1Mjc1MjI1OTAzODQwMyIsIjE0NjEyNTE4MDA2NDkzOTk4MDM3MTQ5Mjk5NjQ3OTc0MjM3NzcxNTUxMDcwMzEyMDk2ODgyNDA3NDQwNjUxMDUyNzUyMjU5MDM4NDAzIiwiMTQ2MTI1MTgwMDY0OTM5OTgwMzcxNDkyOTk2NDc5NzQyMzc3NzE1NTEwNzAzMTIwOTY4ODI0MDc0NDA2NTEwNTI3NTIyNTkwMzg0MDMiXX0seyJpZCI6MywiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIyMTEwNTk0NjE4NzQzODg0ODMyNDkwMDEwMTg1MzAzMTEzNzQ5NDI2NDI1Mjg5NTI4ODQxNTA2NjQyODY5NzU4Mjg1NjIxMzU3MDI1IiwiMTE5ODUxNTAwNjc0NTI0MTQ5MTc1NTQ3MDQ4MTUzNTQxMDgxNzk2MzE1NDE5OTA5MjA4NzA1MDY3MjgwMjA3MjE0OTEzOTcwNjkxMjIiLCIxIl0sInBpX2IiOltbIjE0MDM2Nzc2MTM4NzU3NTMxMTk1Nzk4MDY2MTc4MzYwNjU5OTA4NTQ5NTcwMDE3ODI1NDAwOTc5MzIwNjk5MDE4Nzc2NTUxOTcwNjIzIiwiMTc0NjAyNTUzMjI0NTI2OTg3NzI2MjEwMTA0NTA4OTU2NDIwMjY0NjU5MDU3MDAwMDAzNzQ0MjU1MzQwOTk3MDg4MTY1MDE5MzQxNjciXSxbIjExMjExMDUxNzcwNDMzNDM2NjQwNDI0NDIzODE4OTYyNzE1OTU0NTEyODM0ODAzNjc4MjEzMTQ0NzczNDY0MDQwOTUzNjM1MDM5ODc2IiwiNzA2NjQyMDc1MDc1Njg2MjU1MjU5NDYzNTI5Njg5NTA4NTE0ODk0NDkzODQxNjc5NzY3Mjk4MTUxMDE1ODQ3MTIyMTA4MjgzMzA5MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTUwNjU1ODM5MTY4NDQ0MjE2OTE5MTc2NzUxMjI3MzkxMzgzMTA0MzQxOTY4NjI3MTA2Njc5NjE3NTcwMzM0Mzk2MDQ2MDk0MDA5MzAiLCIxNTI5NDkxMDg0OTEyODc5MjY5NDQxNTM2MzkwNTE5NDU5NDI4NDM3MzczODE3OTQxNjI1NDY4NjgyOTg4NDY2ODUyNDE5NzY1MDE4NyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMjEwMzU0NjMyNjY5MzE0MTUzNjkzNTIyMTQyMTY2MDkxMTgyOTU3Mzg4MjcyMDc0MDU5NDQ0MjM1MTA4MjAxMTIxNDcxNjExMTYzMDMiLCIwIiwiMCIsIjEiLCIzIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDk3MTc3NDMiLCIyMTk1Nzg2MTcwNjQ1NDAwMTYyMzQxNjE2NDAzNzU3NTU4NjU0MTIiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMCJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd1dzV0eWRaN0FBZDNlZndFcVBwcm5xamlOSFIyNGpxcnVTUEttVjFWIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3pva3ZaNmtNb29jS0p1U2JmdGRaeFRENnF2YXlHcEpiM200RlZYdGgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjc2NjU5MDYyMDQzMjYwNjU2MDAxODgyMjQ2MjQ5NDU4NTIzMjkyOTY3Njg5ODQ2Mzk2ODgyOTk2MDAzNDAzMDg1OTQyOTk1NzQ3MTkiLCI5MDc4NTU4OTI2OTQxMTI2MjM0NjQ1MDA4NjIyNzU0MjkyMjIxMTI0NTQyMDE2MzQ1NDMwNjEyMDUyMzU1MDkyMTQzNTUyMDMzMzciLCIxIl0sInBpX2IiOltbIjYxMzU5NTAyNDczNjg2MjE3ODc0Nzc5NDQwNzU4MTA4ODE5MjkyNDU0MjE3NTU3MTc5Mzg1OTY4MTExODQxNjg0ODg3MDYyNTk1MDEiLCIyMTgyOTQzMTc3NzUyMTY0NzQyMDUzMzYwMzA1OTE5MzY0MTMyMDY1NzYyNjE2OTc3NDA5MjIwMjI5ODExNDc5NTE4NTU2MTg1MTcxMiJdLFsiMTM4MjIzMjQzNjU2MTM3MDMwOTgxNDY1MzkxMjU2NjM2NzUwMjU4MDg4Mzg5NTY1NDM4NDU2MzY2OTk0MTYyNzkwNDkwMDA4Njk3NDUiLCI0Mzk4ODEwMTUzNjIwNDk5ODkyOTg3MzAwODkzNTgwMDM0ODQ4ODU2ODAwNzIyNzIyMTMxMTQ5MzkyNDA1ODg1MjU0NDc4OTYzMjQ2Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMDE1MDEyNTMxNjY4OTAzOTE1Mzc2OTYwMDA4NzMxMTI2NDU5NjA2NTU4NTExNDU4ODE5NzA4ODczODE3Mjg2OTUzNjI5MzgxODgyNSIsIjEzMTc2NDA1MTUwNDIwMDIyNzg1MzMyMzI4Nzc1MjYzMTY0MzAxNjA4ODIyMjM2NDgzMDg1NDUzNTQ1Njg5NTQ5MjkwMjQ2MjI0NTA4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiNTA0MDgzNzU5MDU3MzQwNjA1MjY2Njc2NTQzODAwODQxMjU0MzEyMzEyMzQ4MjY4Nzk0NDkwNDc0NjI5OTkwNTM4MTI5OTA0NTYxNCIsIjAiXX0';

    const verifier = new Verifier(packageMgr, proofService);
    await verifier.fullVerify(tokenString, authRequest, testOpts);
  });
});
