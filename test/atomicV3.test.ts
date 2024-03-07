import { Verifier } from '@lib/auth/auth';
import {
  testOpts,
  resolvers,
  MOCK_STATE_STORAGE,
  getPackageMgr,
  registerBJJIntoInMemoryKMS,
  getInMemoryDataStorage,
  schemaLoader
} from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  AuthorizationRequestMessage,
  IPackageManager,
  CircuitId,
  IDataStorage,
  IdentityWallet,
  CredentialWallet,
  ProofService,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  RHSResolver,
  FSCircuitStorage
} from '@0xpolygonid/js-sdk';

describe('atomicV3', () => {
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

  it('TestVerifyV3MessageWithSigProof_NonMerklized', async () => {
    const request: AuthorizationRequestMessage = {
      id: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            optional: true,
            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: { documentType: { $eq: 99 } },
              proofType: 'BJJSignature2021',
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    // response
    const message: AuthorizationResponseMessage = {
      id: '59fbefd2-39ce-4346-94f1-49ec86141ba9',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            proof: {
              pi_a: [
                '4931850785213949686128999530866355140504398167046521116795481546947184272648',
                '332774575245859134568137417770603285619416893331837204312155221564587668094',
                '1'
              ],
              pi_b: [
                [
                  '14792271695016162952390815554867533625013692933642600379618564819732493637941',
                  '18215310934256606244114322866050307053902107679161350635408930840065889072916'
                ],
                [
                  '17048410972040698560239088146160392663861669520384562422376544822376801389912',
                  '21559641235416117505150830172567831599407748749353430076073365383629391654250'
                ],
                ['1', '0']
              ],
              pi_c: [
                '1398727697779021690907399287414954376665288113096930249445808929806707726439',
                '627223672270092807254159968400380256577737860448215394733886462613367964620',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '21568225469889458305914841490175280093555015071329787375641431262509208065',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '0',
              '0',
              '0',
              '1',
              '1',
              '25191641634853875207018381290409317860151551336133597267061715643603096065',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1708958378',
              '198285726510688200335207273836123338699',
              '0',
              '3',
              '1',
              '99',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '1',
              '0',
              '0'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const authInstance = await Verifier.newVerifier({
      packageManager: packageMgr,
      stateStorage: MOCK_STATE_STORAGE,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized', async () => {
    const request = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: CircuitId.AtomicQueryV3,
            optional: true,
            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: { ZKPexperiance: { $eq: true } },
              proofType: 'Iden3SparseMerkleTreeProof',
              type: 'KYCEmployee'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const message: AuthorizationResponseMessage = JSON.parse(
      `{"id":"3f660ddb-f658-4e49-8db1-a39c4fdc348f","typ":"application/iden3-zkp-json","type":"https://iden3-communication.io/authorization/1.0/response","thid":"7e5b5847-b479-4499-90ee-5fe4826a5bdd","body":{"message":"message to sign","scope":[{"id":1,"circuitId":"credentialAtomicQueryV3-beta.1","proof":{"pi_a":["4120898270954196501698659371038588054918958563769831287147203948717242014624","8161421339704983205935832143741731851845367466023122838713066272249193414518","1"],"pi_b":[["2016142731671092085823980355087186874971933756399728048657567167042826575596","6793744608145762931207340557274708648520834540854771358056842986732615365330"],["8778588695583532060082422779657036840781757320865763695218580457590480892876","5111155321599578590956823356574570048809420578935237618371137640346580720238"],["1","0"]],"pi_c":["9353868372198554565265355896994535552872689398030095461666762398339915886396","20314706759118669909305881604960039713418625088875647733334383350621059880114","1"],"protocol":"groth16","curve":"bn128"},"pub_signals":["1","21568225469889458305914841490175280093555015071329787375641431262509208065","7777729897445253016468635824802413494952316305513954490382539913235271469351","0","0","0","2","1","25191641634853875207018381290409317860151551336133597267061715643603096065","1","4487386332479489158003597844990487984925471813907462483907054425759564175341","1709716798","219578617064540016234161640375755865412","1944808975288007371356450257872165609440470546066507760733183342797918372827","0","1","18586133768512220936620570745912940619677854269274689475585506675881198879027","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","1","22728440853100433399211827098349696449620101147489499428101651758549307906","0"]}]},"from":"did:iden3:polygon:mumbai:wuw5tydZ7AAd3efwEqPprnqjiNHR24jqruSPKmV1V","to":"did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7"}`
    );

    const authInstance = await Verifier.newVerifier({
      packageManager: packageMgr,
      stateStorage: MOCK_STATE_STORAGE,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('auth with atomicV3 (nullifier, 2 req (merklized and non-merklized))', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7d22275a-b518-45bb-8ee1-85e12abd8532',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '7d22275a-b518-45bb-8ee1-85e12abd8532',
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
              groupId: 2,
              allowedIssuers: ['*'],
              type: 'KYCAgeCredential',
              proofType: 'BJJSignature2021',
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
            circuitId: CircuitId.AtomicQueryV3,
            optional: false,
            params: {
              nullifierSessionId: 12345
            },
            query: {
              groupId: 1,
              proofType: 'Iden3SparseMerkleTreeProof',
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

    const verifier = await Verifier.newVerifier({
      packageManager: packageMgr,
      stateStorage: MOCK_STATE_STORAGE,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjVkYmE0ZGU1LTMyODQtNDM0ZS04ZDJmLTk2MzliMDQ2MDdhOCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZDIyMjc1YS1iNTE4LTQ1YmItOGVlMS04NWUxMmFiZDg1MzIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiNTgyNDc2NDA4Njk1MjU0ODM4NDM0NTI4MDExOTkxNTU2MDkzMjk3MzI1MTc5ODY1Mjg5NTkwNTA5NTg2ODg1NTg4MzE1NjU0MTU3NCIsIjEyNzIyNTMxOTkzMjg5MTAzMTI2NTA5NDExMjQ0NDMwMDM4NzIzMDAzMDg4OTI4NjU1NjI3OTA2MDIxMzMwOTMxMzAyMjAyMzUwNTI0IiwiMSJdLCJwaV9iIjpbWyIxMzc1MzU5OTUxNjQ5MTAwMjQyMjcwNDQxNzI3NjY1ODc2MTc4ODA4ODk2MzQzNDIwMDQwMzcyMzE1MjU0NjIzMjU4OTIxMzM2ODAzNCIsIjExMTE4MDQ3MTM0NTg4OTIyOTM5MTc1OTU3MTI2MzEyMTIyOTI1MzE2NTc0OTA0NjE2ODI2MDExNTY0NDk1MTI0MjI1NzAyMTA2MzY0Il0sWyIyODUwMjg5MjQzNzIxNjgxMjMwMDAzNTQ0MjY4OTI3ODU4OTUzMTU4MTQzNTExMDUyNDE0ODcxNzcyMjgwODU1ODM3NTM0MDg1MjE1IiwiODAwMjIyMzc0ODM0NzAwNjAxMDg1NjI2NzE3ODMzNDE4Njg4NDg0Mjc4OTQ3Njk1MDE0MDE1MjIxODc0ODQ1ODk1MDU5MzUwNzkzOSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTE5MTI0Njk0NjU4NDUyNjUxODQwMzEzODYzMDU4MTA3Mzk1NjE0NjQ3NjIzNzQ0Njk2ODMyMTY0OTQyMTkwOTkwMTg0NTYzODQyNjEiLCIxMzIwMzA1MTc2NjE3NzkxNDQ0NzMzNzk0NzQ4OTU5OTEzNzA5NTA2NDQ0MzkxNzQ1NDExMDIwNDYzNzI5NzAzNjk0MTUwNjUzMzkzMCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIwIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTc1MzI0NzcxNTI1ODc3ODk0NTMxNDc0MTE4OTc0OTM0MzA0MTMwMDY4MTg0MzE1NTMwNjQyNjEwMTAxOTY4ODQ3NTI3MTU3NDY1MDEiLCIwIiwiMCIsIjEiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDk3MTYzODYiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIwIiwiMyIsIjEiLCI5OSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjAiXX0seyJpZCI6MiwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIxMDkxMDUyODcxNTU1NTA1ODk5MDE0MzkwOTU3MTkxMjA5MDgwMjAyMzk4NjU2MTA3OTcxMjQxNjA3MTE0NDIwMDM2MDc5Mjk4NzM0MiIsIjE1NDExNDc5NDYyMzQ0NDc3NjExMzMwMzExMDI4Nzc1NDA3Nzk4MjM0MDQ0NTY4Nzc2MTM3NzUxNDUxOTE4MzI4Njk4ODkzMDcyMzUwIiwiMSJdLCJwaV9iIjpbWyI5MDM4NTEyNTQ5MDE1NTcyNDIzNjg5MDU4MjYxNDYxMTMwMTUxMTEwMzA2MDc0MTgwNTY1MjcyNTM2MTIyOTgwNzA2OTY0OTY3NDE0IiwiMTE2MTYyNzQyNDQ2NTY5NTUwNTYyMTAxNjU4MDU2MzU4Mzg3NzcyMzg1Nzk2MzQ0OTQ1MjA4MDE4MzU4NDI4MTU5Nzg4OTQ5NzQyNjgiXSxbIjExNDMwMzEzODgyODk0NzA4MjIxNTA0MDY5NjU0NjAxNjE1MzY3MTM4ODI4OTE1NzU3NTg1NzgxNTAyMjAzODg1MDU5NTUyNTUwMjE4IiwiNzk2NTMyMDk4NDY4Njc3NTAxMTM5Mjk1Mzg1MDkxNDQ1NjQzMjMwODQ5ODc3ODAzNzA1MDAwNTgwMzgyMTE2ODI2NjU0MTcwMzUzNCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMzUzNjkwOTY3MTk0MTM2MTUyODgwNjE2MzQzOTY4NzI3OTE5NDU3OTc2NTI5MTAyMDE3MDMzODYwNTQ2ODE0MjEwNzA2NjQ5MDc2OCIsIjIxMTI2NzQ0MDI1NzA2OTk3MjIyMDY0MzQ4NzIwMzMwNzc2NzA0MzA5Mzk5ODA3NjEwMjYzNzUzODM1NTU1Nzg4NjQ3NjYwNzk4MDY5IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjE0NzY4NDE0OTk0NjExOTEyNTkxOTE3MTI4NzkzMzczMjk3ODg2Mzk4MjM2MzE1NDg2NzcxMDczOTM3OTc3NzA2MzE3MDQyNjk3ODg5IiwiODk4NTI2MjY2MzQyMzg3NDA3ODk4MDcyNjAyNTk3MTkzMjc0OTI5ODU3NjYxNTY5NTI4NDg5Mjg0MjQ4MDQxNDE5MTUxNDg4MTA5IiwiMjEwNTE4MTY0Mzc3MTE5OTgwMTcyNDkwNTA0NDQyNDQ3Mjc4MDY4NjEwMjU3MDc4MDQ4OTc4MTM5NTE4NDIyODY2OTAzODI0NzI5MjciLCIwIiwiMiIsIjIiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwOTcxNjM4OSIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjEyOTYzNTE3NTgyNjkwNjExNzMzMTcxMDUwNDE5NjgwNjcwNzc0NTE5MTQzODYwODYyMjI5MzE1MTYxOTkxOTQ5NTk4Njk0NjM4ODIiLCIwIiwiMSIsIjE3MDIyNTI4MDAwMDAwMDAwMDAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxMjM0NSJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd1dzV0eWRaN0FBZDNlZndFcVBwcm5xamlOSFIyNGpxcnVTUEttVjFWIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3pva3ZaNmtNb29jS0p1U2JmdGRaeFRENnF2YXlHcEpiM200RlZYdGgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjE1NjQ4Nzg4NDQ4NDQ3OTYxMTQwNDUwNzM5OTU4MzU3OTM2NTI2MzQ3MTc4OTI1ODE1NzA3ODE1NDQ0Mzk4MTg4MjUxMzg4NTAyMzU1IiwiMTgzNjUwMzQzNDE3MTg2ODI2MDU1ODMzOTI2MDY5OTgxNzkzMjI5MjU5NzY5MTI5NTI1NjM0NDY5ODMyMDQxNjI4NjU2ODMxOTAyMSIsIjEiXSwicGlfYiI6W1siNTc2MzM4NzQzNTU2ODYxNDQwMDE0MTMyNDk2NDEyNTM2MDUwMTM4MjExMTcxNzE5MTIxODQzNjM5MDExMTY5MzgyMTM5MzIwMzg4NiIsIjkyNjM5MDg0NDkzODYwNTQzMjY3NDMxMDA1ODY0Mjk2ODM4NjkxNjM5OTkyMzAzMDM5MjA2NTI1NzEwNTQ2ODMxMTI3MTM3NTg2OSJdLFsiMTQ3MDg0MDI3NTE0NTI0NzQwMDc0OTczNDkxMDM1MDg2MDUyNjQ2Mzg0OTE2MjYxODc1Mzc3MDQ2MjA1ODIxMjY1NzU0OTk5MDI3OTQiLCI0NzQ1NTgyMTIwMjIxNTQ0NDAxMTM2ODUzOTQ3NTQ4MDE1NTQ4MDM2MDgxMzc3MTIwODkwNjg0NDQxNjUzOTYxMTg2MTE5NTg4NTU1Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxODA5MjQ2Mzg4NDM4OTY3MTM2MTA2ODg4MjMzOTMzNjQ4OTA0NDI3MTI4Mjg0NjYxNTEwODU4ODE4ODQ0Mzc5NzU2Nzk2ODQ4MDU5NyIsIjEyODI4MjkwMzk2Njk5NTM4OTc2NDM5MzMwODU2MDc4MDE1NjQxNjIyMDgxNDgwODU3NTUzMTEwMDY1MDkxNzIxMDA0NjMwMzAwMzc4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiNDY3OTkxOTk5MTQ0MTMyNjM2OTQ5NzEyNzYzMTU2MzQ0NDk0MDM2NzExMjUxMjQ4MzgzNzA1MTgyNjYzODQ0MDk0Nzc0MDg4NTE4OSIsIjAiXX0';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
