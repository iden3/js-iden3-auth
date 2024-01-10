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
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjAyMGZjZDdjLWM4MDgtNGE4Zi1iZWY1LTQyNmUzZjEzN2M1NCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIwYTkwNzViYi02Nzg2LTQzNTQtYTc0Ni0xNjc5Y2I1OWMzYWIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMCIsInByb29mIjp7InBpX2EiOlsiMzYzMzQyNDI1ODQwMTY4OTI3MTYzNzU5NDIyMTIxOTgxNTU4MTM1NjQ5MDAyMTQwNjMzMjY5NzEzNTk1Mjk2NDgxNTEyMTM1OTA3OCIsIjE2NjA4ODcwOTE3MTY3NTE0NTIyMzQ3OTU3MjIyMDQxNDAyOTM2OTU1NjkwODI5MDI2ODM2OTU2MjM5MzQ0NDg3MTUzNzQzNzM2MjQ1IiwiMSJdLCJwaV9iIjpbWyIxNDM3MjQ5NzE0MTk3MDUzMjE5NTM4MzU1NTI0Nzk1NTU5OTQzOTAyMDg2ODg2Mzg3MTEzNDE1MzU0MzM4NDc2MzIxNzYzOTU1ODE4NSIsIjE4MDU5OTU2MTkxNjUzOTc1Njc3OTAzNjQwMjEwMDkzMDAyMzM3MTQyNTEwMDA0ODgzODU2NjM2NzQxMzY0MjEyMDMwMDkxOTMxNzk0Il0sWyIxNzc3NzY2MzYyMTgyNDAyNDEwNDc3NzIxMjI1MzI1NTUzNTIyOTUzMjg2MTUzNTM1NzM3MDA0OTc2NTYyMDMxMjMyMDEzNTI5MzUyMyIsIjg4NzQ2NTI0MDk3NTUwMzQ3OTc0OTgyMDU5ODczNjU3NTUyOTg3MDU3MjYzOTQ3NzQ3MDY2NjE4NjM2MDA2NzAxNzQyMjczMDU1MjMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjg1OTc5MzUwMDAxNzY0ODU3OTQ0NDEzNDM1ODAyNTYxODg3NDk5ODU2NzAwOTM3NjM4NTY0MDg1MzYzMjk3NDQzNTI3MTY5ODAzMDQiLCIxNjk1MzkzMTg2NTcyNjA5ODE5NDk5OTE5NTI0NDMxMjI1MjgwMjQ3NjgwNzc5MTI1OTQwNzgxMjIxNTI4MTM3MjQwNDMwNDE2NDM3MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIwIiwiMjE1NjgyMjU0Njk4ODk0NTgzMDU5MTQ4NDE0OTAxNzUyODAwOTM1NTUwMTUwNzEzMjk3ODczNzU2NDE0MzEyNjI1MDkyMDgwNjUiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMjA2NDE5NDAzNDk5ODcyMjMzNDMzMjkzODEyMzM4MTIyNDA1MjIzMjQwNjYyNzEwMjc2OTA0MjIzNDY0MjUzNjcwMjczMzI3ODUzNjkiLCIwIiwiMCIsIjEiLCIxIiwiMjUxOTE2NDE2MzQ4NTM4NzUyMDcwMTgzODEyOTA0MDkzMTc4NjAxNTE1NTEzMzYxMzM1OTcyNjcwNjE3MTU2NDM2MDMwOTYwNjUiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MDQ4ODQ5ODUiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIxIiwiMCIsIjMiLCIxIiwiOTkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy1iZXRhLjAiLCJwcm9vZiI6eyJwaV9hIjpbIjE5MDkxNzMwNDgzOTUyNTIzMzIyMTc4ODAzMzIzMzM5MDQxNTE4MzU3MTEzNzMyMDM2MzczOTI3NjE2NjExOTA2MTA4OTQ4OTEzNzQ5IiwiMTAyODQwMjUwOTk5MTM5NzA3MjEyNjIwNjU5MzI3NDY3OTAwOTAxMTc1Mjg0MjI0NzI2Nzg0ODk1NzU3NDk5NjQxODYxOTAzOTQ0ODIiLCIxIl0sInBpX2IiOltbIjE4ODgzNjIyOTcwNTg3NzM5MTAwMjg5OTE2NDYzODE4Njg5MjExMjI5MTQwMTA1OTcxMDI1NjAwMDQ4MzI1NjM2MjU0OTE2NDExMDg2IiwiMjE3NzE5MDcyOTc1MjI3NTA0OTg0OTczNjA4NzIzMjc0MDg5NzAyOTI2NDE2ODM4MjE4MjM4MzQ5ODAyMTQ5NjUyOTU2MzgxNTM4ODYiXSxbIjEwNzIzODA0NjE1MTQ4NTMyMjQ4OTY0MDIzNDcxNjc4MzIzNjA5MzA0MzM5NzU2NTIzNDA3NzUwNTU3NTAwMTkzMzEzNDMwNzQxNTMxIiwiMTA1ODI0NTE2OTA5NTc1NjgxNzQyMjM3ODQ2NTA0NzMwNTY4MzAyODE2ODU1ODMzMDM0NzU5ODg4MDYzNjUyOTYwNzY4NDM4OTExMjIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjc1MTk4NzQyODg4OTYyOTEwOTY5MDk5NzgzMTg3NDA4MDU1OTc2NDcyNzY1ODQ4Nzc0Mzc2ODE0NzYxMTk2Mjg3MTkzMTUzMDI2MyIsIjE5MjA5MTk1MDg1NTQ4NTM2Mzk2NTMwNDM5NDA2OTU0MzA4MDcxNzA2MTM3NzYxMjkwODc2Mjk4OTA1NDI5MzgzNjM5NDUxNjc3MzU2IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjM3NTAwNzExMDA4MzQzMjgwMzc0MjA1MDQwMDQ5MzYxNTUyNDE5Mzc2ODczODA1NTg5NTI1MDU0Mjg3Njg1MDY4OTkzOTQxMTc2MTEiLCIyMTU5NDY0NjkzNzA3Njc1MDgxMTk0MDI0MDAyMTA0NDEyOTY3NjM5OTYzMDgxNzA4MTQzMzk5MTIyNDg3OTc0OTE3MzcwMDIyMjkwNCIsIjAiLCIwIiwiMiIsIjIiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwNDg4NDk4OCIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjAiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEyMzQ1Il19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3V3NXR5ZFo3QUFkM2Vmd0VxUHBybnFqaU5IUjI0anFydVNQS21WMVYiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3em9rdlo2a01vb2NLSnVTYmZ0ZFp4VEQ2cXZheUdwSmIzbTRGVlh0aCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjE4MDE1MDI2ODk5Nzk4OTk2NDYwMjI0NDA1NjQwMjU1MTc0NzgyMjcyNjQyODYxNTY2OTkwMjY2MDEyNzU1NDk4OTE1NzU0ODI5MzA3IiwiMTcxMTYyNTEwMTYwNTUyMTE3MDM4NjIzODUwOTgyMTEzNzIxNjA1Nzk4OTE5MDE4OTUyMjE4MDYxMDE3NTMyNzA4ODMwMjMzMDQyNTkiLCIxIl0sInBpX2IiOltbIjQxNzM4OTE2MTkzNDgzODE0NDM0NTIwMjcwNDQ3MjUzMTI2MDY5MDA2NzY4MDk2ODI0MjM0MTg1MTgwNTkzMzY3MDgyMDY0NDQ3MTAiLCI4NTkzOTMwODQ2MDgzNzc0OTQ0ODE5MjQ0MzE3ODg4MzU0MjQ0OTQ0NzM2OTgzMzI4NjUwNTkwMjY3NDQ1ODAxMzk0MDMxNTAyMzA1Il0sWyIxMTk4ODE3MDM3MTA1NzY3NTMxMzQyNzcyOTc3Mjg5ODAwOTEzMTgwNDQzMjY3MjQyNzYwMjY3MzQ3MDY0NjA4MDg4MjczNjI1NDA2MCIsIjQ2MTYxNDYyODU0NTY3NDYxODM4OTk0NDA3ODgyMDg3NjQ1MzY3MjY0NjQ2MzMzODMyMDA3NDkzNTgyNzg4OTg2MjEwNzIwODk1MDIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjQwMjY1OTUwNjQ1MDQ5MTU3Mzg5MjM1MTIyNTQ5OTg1NjIwMDc0Nzk3ODY3ODMxNjkwMDY4MzQ3NzcyNDkxMjE2OTM2MzI4ODMwNjYiLCI4NjgyMjg1NjE5MjE2ODk2NjYwODg5OTczMTAwNDc0MzU0MzgwMzM0Njg5MDA0NTE5Njk2NDcwNDM2MDE2ODg3MTY4ODMyNDk0MTc5IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiMTY1ODE1NjAzNjk3MDY3MjQ0MDM1MDY0MDgzOTY4NzEwNzgxMTY2MzIxOTI4MjQ0NDA4MDYyNjE5ODIzNjc3MTgzOTI3OTc1MTY5MjciLCIwIl19';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
