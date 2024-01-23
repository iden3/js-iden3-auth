import { Verifier } from '@lib/auth/auth';
import { testOpts, resolvers } from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  AuthorizationRequestMessage,
  cacheLoader,
  CircuitId
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
            id: 84239,
            circuitId: CircuitId.AtomicQueryV3,
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
            circuitId: CircuitId.AtomicQueryV3,
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
            circuitId: CircuitId.AtomicQueryV3,
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
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjIyNDIxNjFmLTEzNmUtNDVlYS04MzUyLTU4MmFiMDZiZDY3OSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZDIyMjc1YS1iNTE4LTQ1YmItOGVlMS04NWUxMmFiZDg1MzIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMCIsInByb29mIjp7InBpX2EiOlsiNDE2MTE2NTEwOTYwMjkxMDQ2MjU2OTI5MjcwODk4NzE2MTkzOTA3NDQzMjcyNzIxNjU4ODg0NzEwNjMyNzQ0NzI0MTQ4ODA2NTMxNSIsIjE5MzczNDA5NTQ2MzM4NDAwNzQxMzk1MTYyNjMyNDcyMDg1OTgyNjA5ODE1OTgyNTUyMDYwMDgwMjY3NDE0OTYyMzkwNjA2OTMxMTIyIiwiMSJdLCJwaV9iIjpbWyIxMjI2MDUwMjE3MTQ0NzM0NjQwNzA0Nzc0Nzc1NjYzMzA5MjUwMzU5OTAzMDcxNDcxMzM3NDEwMzc0Mzc1MTYwNTM2NDMwMzg3NjAzMCIsIjEzMTg4OTc4NDExNzU1MzExODkxNDQxODA0ODQ4MTA5NDA3MzgwODkzNjU2MTc5MzMzNTA3ODUyNTA5NjM5NjQzMzk0OTc4NjgyNTk2Il0sWyIxMDc5MDc1MTc0MzU4NzU0OTgwMzczMzU0NzIzNDQxNzk0NzY3Mzc2MDU4OTM3OTQ4MDQ3NDE0NTk0NTYzODk3Njk2MDU0NTg4NDg1NSIsIjQ2Njk0NTc1NzA1ODI0MTg2NTgyMzcyNzM0NDgxNDQwMjI0MzcwMjI1NzQzODkxNzkwNzEwMjgyOTIxNDgzMDIyMDA1NTg4OTQ0NTciXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2MDcwOTUyMzI4MzA1ODM0Mjk0MzQ2MDY5MTgzMTExOTg4NDI5MzEyNzk4OTE2ODQ2NTM3MDM5ODIyMTQwOTIxNDIwODg1NzQ4Nzg0IiwiNDQzNjg5MTQ4NDMwODcyNTA5MDkxMjE1OTA5NjMxNTg2Mjk4MTQxNzM5NTQ3NDgxMjIzNzI4OTM5NTA1MzA1MTQxOTg2NTE5ODI0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIwIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTg0OTgzODY0NDE2MzY0Mjk2NzAyODMwODAyODYxODU5ODc5Mjc1NjI1MDI5ODUxODI5NDUzMjc0NzIxNjE3NjMyODA5Mjc0MTE0MiIsIjAiLCIwIiwiMSIsIjEiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwNjAwODAxNCIsIjE5ODI4NTcyNjUxMDY4ODIwMDMzNTIwNzI3MzgzNjEyMzMzODY5OSIsIjEiLCIwIiwiMyIsIjEiLCI5OSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy1iZXRhLjAiLCJwcm9vZiI6eyJwaV9hIjpbIjE2MDA1NjY4NjMyNjQ3ODIyMTYxNzQwMDczNDA4NzcwMjU1MjAxMTUyODI3NjY3MTgwNDg1NDQ0MDU1ODM1MjU5NzA4NjQ1Mjc4MjUiLCIxMTM1MDQwOTE4MTIxMjM2OTEzMTAzMTg0NTM2ODgwOTU0NzgxODkwMjA2MzYzMjkzNTA3Njg0MzIxNTIyNzM0MjU3NjY5NjcwNTU5IiwiMSJdLCJwaV9iIjpbWyIxMjQ5MjM0MDIxNDMyNDQ3MzI4NDI0ODc4ODQ5NDc4NjkxMDAzMTQ4MjI0NDI5MjE2NjY0MzM2ODEwNTUxNTg4MjUwMDMwOTQ2NzA3NSIsIjE4NTY2OTM2MzM4MDM1ODk1MTQ4OTY0NzMzMDc3MjEwMzg2MjEzNTc2ODY5NjgwNzI3NTg1MTI2OTQ1Njg5NjE3NjQzMzQ5OTcxMTU4Il0sWyIxNTc1NzEyNjA3MTU4MTE4OTk4Mzc0MDY3OTI1NDczNDg1OTA2NjM0MTMzNjQ2MDUxMDE4OTgxNTkxNjY0OTE0MzM3Nzk5NDU0MjczOSIsIjE0NzMxMzY2NzE0NDc1OTQwMjgxNTMxODIzNjI2ODcxMDIyNzE1OTYxMTE4NzY2MDY5Njc1NjU1ODE0MDY0NzI3NjYzMjkzMTUyNjMwIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI5MjkyOTcwMDkzNDA0MTYyNzc1Mjg2ODIxOTQ1NzA5MDQzNjYyODE5OTc5MTU2NTkwNTQ4NTExNDEzMDE4NDcwNzU5Mzk5OTEzMzY2IiwiMjM3NTAxNjYyNTAyNTg5MTkzMTc2MDY1MTY3NzI0MDA3NDQ3MDc1NjkzMzUxNjEwNDY4NDc1NzY1MTQ5OTA3ODY3MzQwNDA3MTA0NyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI2NDc3NzYyMzAyMzI0NDkxNjIzMjI4MTkwMTMyNTY5NTEyMjEyODE1ODQ0MzQzMTE0OTM2MjIxMDEwMTQxMzQ0MzM5MDkzMjM2NTUxIiwiMTIyNTMzNTk4MTAyMjk0MzAxODMxNjE1OTk2OTgyNTA4MTA4MTc3NDI5Njc1MzE2OTAxNzI1NDczMzY5NTkxNjg3MzU1NDM5MzI1MDgiLCIyMTA1MTgxNjQzNzcxMTk5ODAxNzI0OTA1MDQ0NDI0NDcyNzgwNjg2MTAyNTcwNzgwNDg5NzgxMzk1MTg0MjI4NjY5MDM4MjQ3MjkyNyIsIjAiLCIyIiwiMiIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzA2MDA4MDE5IiwiMjE5NTc4NjE3MDY0NTQwMDE2MjM0MTYxNjQwMzc1NzU1ODY1NDEyIiwiMCIsIjEyOTYzNTE3NTgyNjkwNjExNzMzMTcxMDUwNDE5NjgwNjcwNzc0NTE5MTQzODYwODYyMjI5MzE1MTYxOTkxOTQ5NTk4Njk0NjM4ODIiLCIwIiwiMSIsIjE3MDIyNTI4MDAwMDAwMDAwMDAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEyMzQ1Il19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3V3NXR5ZFo3QUFkM2Vmd0VxUHBybnFqaU5IUjI0anFydVNQS21WMVYiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3em9rdlo2a01vb2NLSnVTYmZ0ZFp4VEQ2cXZheUdwSmIzbTRGVlh0aCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEzOTM3OTI3MDY0MjMwMjI0NTAyNjkzMzU0NDUwMzM2NTc1NDMwNzQ3MDAwODg4ODAwNTA3MzIzMzgwMzU4MDQ2NjgzMTQ0MjU5ODg4IiwiMTc0MDY0NDU5MzgyODQwNDU0NTg4Njc0NzUzMjEzMzcyNDc5MjE4NTg5NTAwNDk1OTI1MzIyNzk3MDczODE1MjY2ODkyMDY1NjcyMDYiLCIxIl0sInBpX2IiOltbIjE4NDcyNzMwNTU2OTU1Mzk0OTQxOTIzMzk1NTA2ODM3MTMwNjMzNDAyNTQwMTQyNTUzODQ1NzU3NjY4ODE3NjYyNTAxMjkxNDkyMzM5IiwiMTI0ODEzNDMzNDg5Njg2MTk1NDA0MjUyODY5MjExODY0NDk5MTM2OTgyMTIxNTU2MTQ3MDIzNDIwNzkyOTMyOTk0NTc3NDk0NjEzMDUiXSxbIjQ4ODUwNjkyNDkxMjc5ODU5Mzk5OTM2OTU2NzcyNDQ5ODgxNTY0MDA1MDU2MzcwMDUxMjcyNTU2OTcyMzM3NDI1NTY0Njc1NTkxMDMiLCIxMDA5MTkxNTM5MTQ1MjY5MzQyMjM3NzA4MDA5MDY5NDQxMDIzMzE5ODM1NjcxOTk3NzI1NTcwMDkwNzc4Mjg2ODQ2NjA2MzYyNjM5OCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTAxMDE2NTc0Njc4NTExMjM2Nzg0MDgxNzM1MjMzMjQyMjk0NjkyMjIzNTYzNjA0OTgwMjYyMTE3NzY3MjU4Njk3NzM1MjUxMTYzMjQiLCIxNDczMjQ0Njk5NDUwOTYzNDQ4OTE2NzI1NzQzNTU0MTEwMjA4NzU3OTk3MjIwMjY2NDI1NzM3MTg3ODE1MDAyNTYwMTcwOTcyODgxOCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjE0NDAxNzkxNzYwODkxNjQzMzQyMTkwMDY1NDUyMTY5NjAxNjAxNTQ1MDYwMzQxODg4NjMxODk5OTYzNzAxOTk1MDcwNDcyMjMwNDE4IiwiMCJdfQ';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
