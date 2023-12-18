import { Verifier } from '@lib/auth/auth';
import { testOpts, resolvers } from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  AuthorizationRequestMessage,
  cacheLoader
} from '@0xpolygonid/js-sdk';
import { DocumentLoader } from '@iden3/js-jsonld-merklization';

const schemaLoader: DocumentLoader = cacheLoader({
  ipfsNodeURL: process.env.IPFS_URL ?? 'https://ipfs.io'
});
describe('atomicV3', () => {
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
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
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
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            proof: {
              pi_a: [
                '15208931239306667614189217356426367087296508213411046833716711442163868780112',
                '20490648944065703271613941501811057996992005137106581261392868037192830801319',
                '1'
              ],
              pi_b: [
                [
                  '9658837325736932089175519161219586340790605854199431170964132439402760343882',
                  '2229712957417570067219766417050901639838551011053815708957384652110672096636'
                ],
                [
                  '8001092431519117455354797520811940294780537362771012429305941024017334317686',
                  '14862879727984936294040948959940841120433831193863247939940900720892674782281'
                ],
                ['1', '0']
              ],
              pi_c: [
                '10979201893913563932568403855542624651100292054247823659266571152101750130209',
                '21286864035525845180147694216456377751365547090829007463506610939813242720910',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '22466018227912887497595444357663749526852544754809814096731120723497783810',
              '7232286365358812826682228661780467195854751779823604018938921042558237169817',
              '0',
              '0',
              '0',
              '1',
              '84239',
              '26675680708205250151451142983868154544835349648265874601395279235340702210',
              '1',
              '7232286365358812826682228661780467195854751779823604018938921042558237169817',
              '1702457100',
              '198285726510688200335207273836123338699',
              '1',
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
              '22728440853100433399211827098349696449620101147489499428101651758549307906',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qFXWZVHKTaYX1vmTGtStgRq1s8vUWhQ7HLjtqb2fV',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
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
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            optional: true,
            query: {
              allowedIssuers: [
                'did:polygonid:polygon:mumbai:2qKKc4jxAhabrdFrAF3iC7boycfdQmWXq2qTBU4sPc'
              ],
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

    const message: AuthorizationResponseMessage = {
      id: 'a8ceddf8-24c8-4797-bb94-234a17c6b551',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            proof: {
              pi_a: [
                '2191675399003747228361650328748147195525067334657244384911902711268678817802',
                '19948479904115663964234685946314006853666845209972027887002197866333362304394',
                '1'
              ],
              pi_b: [
                [
                  '422189606437031219571968003421368368386938453003241975855652752251201163758',
                  '9263822572774254449054388930060153687464515712228765747368750307969672340141'
                ],
                [
                  '19293339395101879017873172109004141351276884864694548105955158013357482683356',
                  '2779213239514041287265984937924693652347623320831272361142245115033321578990'
                ],
                ['1', '0']
              ],
              pi_c: [
                '3805936274754036854895936107504061566835912493410231954955974762213052034636',
                '11817318886045212940702535466395270095280111730105021796772613798925818134104',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '22466018227912887497595444357663749526852544754809814096731120723497783810',
              '16501727979801979045409842472064689783782600072880560178348889772807800718289',
              '0',
              '0',
              '0',
              '2',
              '84239',
              '26675680708205250151451142983868154544835349648265874601395279235340702210',
              '1',
              '16501727979801979045409842472064689783782600072880560178348889772807800718289',
              '1702457550',
              '219578617064540016234161640375755865412',
              '0',
              '1944808975288007371356450257872165609440470546066507760733183342797918372827',
              '0',
              '1',
              '18586133768512220936620570745912940619677854269274689475585506675881198879027',
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
              '22728440853100433399211827098349696449620101147489499428101651758549307906',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qFXWZVHKTaYX1vmTGtStgRq1s8vUWhQ7HLjtqb2fV',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('auth with atomicV3 (nullifier, 2 req (merklized and non-merklized))', async () => {
    const request: AuthorizationRequestMessage = {
      id: '29d9fe7e-ea16-49dc-97fd-ba432b857403',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '29d9fe7e-ea16-49dc-97fd-ba432b857403',
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
            circuitId: 'credentialAtomicQueryV3',
            optional: false,
            params: {
              nullifierSessionId: 12345
            },
            query: {
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
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImYxODRjN2ZmLWRlYmUtNDExMi04MGFkLWRhNjMxYzI1Mjg3NiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIyOWQ5ZmU3ZS1lYTE2LTQ5ZGMtOTdmZC1iYTQzMmI4NTc0MDMiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzIiwicHJvb2YiOnsicGlfYSI6WyI4NzkxMTQ1NTMyODc0OTc2NTY1NDg3NTA2Mzk4NjMxMTg5ODA5NzU3MDY4NDY5NDA0MzkzNTM3Mjc4NDI3MDYwNDc4NjgwNjgxMzMiLCIxOTM4MTE5Njk5NjE0MDAxNDgzMjQwMjM0ODE2OTk1MDM4NzE2Mzk0NjkwMDAxOTI5ODQyMTg0MzQ3MTM2MjY0NTUxMjIzNzkyMTQ0MyIsIjEiXSwicGlfYiI6W1siMTk4Mjc0MzgyNjQ2OTkzOTg1MjU0NDU1NTAyNjg4OTMyMjUwOTE3NDExNzA0NDA2Mjk0NTMzNzk2NDI0Mzc4MTMxNDcxNTExMzQ4MDAiLCI2MDgyNDcyOTQ3OTA1NTAyNzczODk3MzQ4MTc4MTQ4NzI4MjY1MzE0MDg1MDE1MTkxODQyODU0NTU4Njk4MjczNzEzNjYyMjYyMTkiXSxbIjE2MDQzNTE0MTc1NDgyMDY1NTEwMDc2NjI5NTIzNjA3OTM4NjEwNDcwMDQ5NjcxODExNDY1NjYxOTUxOTY3MTI3ODg3MjgwNzUzNzI0IiwiODY4MDY1MTE4NzE5MzUxNjk5MDMwMTQ2MDk1NTQ4MTc4ODMwMjEzNDYyMjU0NTgxNTg0ODk5Mzc4OTQyMTE2MDU3NzU5Nzk3NzE1MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTE2MjMxMjM0NjI0NTk1OTYyNjkyMTI4MDgxODUzNDU4NjQyNzE3OTUxMTU4Njg5ODQzNjE5Mzc2NTIxOTI1ODcxOTYyNDEwMTEzODMiLCIxMDQwNzg0ODc5MTY1MTMyODEzMjQzNDkzNDU5ODM0MjkyNzE4ODEzMjI3MzE1MDIzMTM2MDc1ODM5MjgwNDg5NzE1MzMyOTUwNTYzMSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIwIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMCIsIjAiLCIwIiwiMSIsIjEiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwMjg5MTUyOCIsIjE5ODI4NTcyNjUxMDY4ODIwMDMzNTIwNzI3MzgzNjEyMzMzODY5OSIsIjEiLCIwIiwiMyIsIjEiLCI5OSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMyIsInByb29mIjp7InBpX2EiOlsiMzUxNjc4OTc3NTE2NjczODU5OTI1MTUwMjI2NzA5NjU4Mjg4NzExMDYyNjk4MjEzNDMyNjg5NDgwMTE5MDg0ODU2NDkwMDIyMTg1MyIsIjExMjQ2OTA2ODg4NTUxMzA0MDQ4NTI1NDk4NDM3MDIxNDE1MTcxODg5MTc1OTQzNjU0MjcyMTQ0NzQ5NDAxNDQzOTc0Nzc0MTIzMzY4IiwiMSJdLCJwaV9iIjpbWyIxNjQ4MDk5NzQ0MDA4OTg3NDEwMTkyNDQzNDM0NjQ0NzY2NjU1MzMwNzI3MDMwNDA5ODY5MjYyODU1Njc3OTQ5MTkyMjk0OTU1NjE4NSIsIjY5NDg3MjczODk1MjI1MDgyNjcwNzE2MTg4NjExNDY4NTA3ODU3NDUyMDgxMzE3MDYzMzg1MTUwMjE2OTkzNjkyMzgxMTQ0MDQzOTQiXSxbIjE1Mzk5ODY3NTU2ODA0MTQ1NTU1NzAxNTgxMjg4ODM5MTc3ODMyMjg0MTI0OTI1MjgxMDg2NTYyMzI1OTcyNTI3OTY4MTA4NDc3MzI2IiwiMTk4MTgwMzczMDY0MTgzODYwOTAwNDUyMTM5NjQ2Mjc0Nzk2MTI3NDQwODMyNjg0NDg2OTc1MzMwMjgyNjM2MTQwODQwMzkzNDA2MTEiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2ODg2MTUxNDkwMTAzMDMzNzEyNDMyMTc5OTUyMjIwNDA4NDIyODcxMDM4MzQ4NzU3NjQxNDIxMDQ0OTU4MTYxOTg2NDY2NTg2MTgyIiwiMjE2OTQ4MzAwMzc0ODQwMzAzMTM0NzEzOTI2Nzc3ODMyMTY4NjYyMzMyMDMzMzQ5MzY3MTkwNTk1MDU2ODE4Mzc3NjcxNDc3MjkwMDMiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiMTY5MzIxNTc1MzI0MTYyMzQ0ODAyMTE1ODAwNjIyMjkzMDcxMjIzNDAyMTA1MzE3ODkyNTczNzE5NDc0MDIyMDgyNjIzOTQ4ODM5IiwiMCIsIjIxMDUxODE2NDM3NzExOTk4MDE3MjQ5MDUwNDQ0MjQ0NzI3ODA2ODYxMDI1NzA3ODA0ODk3ODEzOTUxODQyMjg2NjkwMzgyNDcyOTI3IiwiMCIsIjIiLCIyIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDI4OTE1NDkiLCIyMTk1Nzg2MTcwNjQ1NDAwMTYyMzQxNjE2NDAzNzU3NTU4NjU0MTIiLCIwIiwiMTI5NjM1MTc1ODI2OTA2MTE3MzMxNzEwNTA0MTk2ODA2NzA3NzQ1MTkxNDM4NjA4NjIyMjkzMTUxNjE5OTE5NDk1OTg2OTQ2Mzg4MiIsIjAiLCIxIiwiMTcwMjI1MjgwMDAwMDAwMDAwMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMTIzNDUiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3dXc1dHlkWjdBQWQzZWZ3RXFQcHJucWppTkhSMjRqcXJ1U1BLbVYxViIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246bXVtYmFpOnd6b2t2WjZrTW9vY0tKdVNiZnRkWnhURDZxdmF5R3BKYjNtNEZWWHRoIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjE1NTA5MTg3MTExOTg3MTI2NDg0MzI5Mjc2NjM4MDIyNTg1MDQ1ODA0NDkyOTgyNjg1NTExNDI5NDE1ODI4MjYwNTQyMTE4NjY0MzU1IiwiMjEzNzYzNTEzMzA2NzMzNzE1MDQzODg0OTY0OTM5MjE5MDgyODY2NTQ4MjQ4MDM0NTQ2NTQzNTI0OTIwMTA5OTMwODEzNTE3MDY2MDQiLCIxIl0sInBpX2IiOltbIjYxNTYzNjUwMDE3MDY2ODc2MzUxOTUwNDg4NDIzNTY0NzY1NzczOTk5MzQwNTIxNjY1ODQzMjA5NTAxMDczODg2OTQ1MTE1NTc0MjYiLCIxNzQ4MzExNDM1MDEzNjY3OTE2MjYwNzA1Mjg1MTg3MDA4OTQ5NTExNTQyMjgwODAwMjU3MjY3Njg3NDEwNzQ1MDUwMTEzNDU3ODU4MiJdLFsiMTIwMzY3MzYwMzk1MjQwNjQ2NTQ0MzYxMTIwOTYwMTc0NzQ5MTcwNjk1MTQwOTQwNjUyMzg5OTM2NDkzOTkyMjY0MzQ4MDEwNDEzNDMiLCIxMzA2MTE1NDg2NDM0MDgzOTgzNjA3MTE3MTA4OTA1NTA2NjE1ODY4ODAxOTc0OTgwNjkzMjM4OTUwMjMwMzE4MjQ1NDg2Mzg3ODQyOSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTA4OTM5ODU0NjQzNDgxNjUwNzM4OTMwOTc3MTY2ODYyNzE0ODIyNTUwNjk5NzA3NDM3Mjk3MDQ5ODM0MTU1OTIzODUzMDAzNjE4NTQiLCIxNjg0NjQxNzUxNjk2NjMxNzkzMjE4NjA3MTU0MDQwODI5MDA4MTk0MjQyNzMxMTc0MTMyMDI0ODU4Nzg5NjY1MzAzOTc2MjExMjUwMCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjE5NDk2OTQ2MDk0Mjk5NDA4NTk1ODUxODMwNDI4NTc5NzEwMzQ2NzIyMDU3NDc1OTAwMTU3MzgwMzE5MDMwNjI5MDA1NTI0MjgyNjMwIiwiMCJdfQ';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
