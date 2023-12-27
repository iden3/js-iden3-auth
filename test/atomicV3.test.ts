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
            circuitId: 'credentialAtomicQueryV3',
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
            circuitId: 'credentialAtomicQueryV3',
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
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImNkN2VlZGQ5LTMxZjQtNDNiYi1hOWFhLTY3OTZjYWE5MWE0MSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZDIyMjc1YS1iNTE4LTQ1YmItOGVlMS04NWUxMmFiZDg1MzIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzIiwicHJvb2YiOnsicGlfYSI6WyI4NDYyNzI5NTcxNTc1NjAyNTUyMTE5NjA0NDU3MjQ2MjQwNjk2ODA2MTIzMzY2MzA1OTMwMTQ4MDUzNjU0MzM5NzY0ODY0ODI0MzU5IiwiNTE3MjY3MzQxMDE1NDc0NzMzMDIyNDQ0ODkwMTM3Njk4MjE2NjAyODUwMjIzMjcyODExNTQwNzk1MzU3MTkyODA3OTgyNzA5MjIyIiwiMSJdLCJwaV9iIjpbWyIxMzg0MzE0NzI0MTkzMzIyODExNTUxNTExNzE5ODQyNjc3MDgwNDM3NzMwNzA1MzQzMzUwNjAwOTU5ODcxMjYwNjAxNzIwNzg3NDA3MiIsIjk0NzAyNjg3Mjc2ODUyMzAzODUwMTkwMTkwNjU3Mzc4NjQwNjI1NjQ1NTkzMTc3NTIxMzIzNDMyNTc5NTM2MjI3NTM2NDQwNTY2MzkiXSxbIjEzNDA1NDg2NzA4ODk0ODUzNzA4NDgxODg0OTgyMzczNjUwNDg2MTg5ODUwMTQ3Mzg2MDA5NTU5NzU1MTIxOTk2MjQ3Nzg5NDEzOTUiLCIxNzUwNjM0NTY0Nzg0MDI0MTk2NTcxNTI0NTc3NjEzOTQ3NTg4OTQyMTY0MjU1OTM4MTM4MjcwODU3NjY4Njk4MjAzNjAwNTE2NDY0NSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjEyMjk1NjY3NDc0OTI3MTIyOTAwMzEwNjQ1MDYzOTY3MTE0Mjk3NjcyNDgyMzQwNjA0OTk5MjkzNzE4Njc1ODIxMjYwMDQ0NDUxMDQiLCIyMjU0NjM0MjI3NDkxNTI4MDA0Mjc3OTQzNzg1MTc1MDQxMjkyOTAxNDE3MDUxMjU4MDU0ODQ3NjEzNDAxNTQ3OTU1Mjg1MjgyNDMwIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU2ODIyNTQ2OTg4OTQ1ODMwNTkxNDg0MTQ5MDE3NTI4MDA5MzU1NTAxNTA3MTMyOTc4NzM3NTY0MTQzMTI2MjUwOTIwODA2NSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCI5MjIyODAyMzQ0Njc1Nzk4NjU3MzQzMzM1MjA5NzA2MzIzMzQ3NjQxOTkzMDI2NDU2MDI2OTQ3NjYxOTIwMjM1Mzc3Mjk1Mzk1MDEwIiwiMCIsIjAiLCIxIiwiMSIsIjI1MTkxNjQxNjM0ODUzODc1MjA3MDE4MzgxMjkwNDA5MzE3ODYwMTUxNTUxMzM2MTMzNTk3MjY3MDYxNzE1NjQzNjAzMDk2MDY1IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzAyOTk0NjE3IiwiMTk4Mjg1NzI2NTEwNjg4MjAwMzM1MjA3MjczODM2MTIzMzM4Njk5IiwiMSIsIjAiLCIzIiwiMSIsIjk5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX0seyJpZCI6MiwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMiLCJwcm9vZiI6eyJwaV9hIjpbIjE3MDk2MDAwNTY0NTUxMjIzMjIxMzc5MDE3NDYwMjA5MTI1Njg1MzMxNjQ5NTUzNzIyNjc0MTAxNzYwODcxMDg0MDA5NjAwNDQyMjc5IiwiMTE0NDA3Mzg4MjQ0MDEwNzY1NjI1OTIxNDE5MTE2Nzg3NTkxMDY2NTQzNTMzNTcwNTAzOTM1NTQzODY0OTcwMDEwNjk1NDQ5NDY3MzQiLCIxIl0sInBpX2IiOltbIjU5OTUyNjMwODcwMzQwNjIyMTk2MTIyOTA2MzU0NDI5MTk0MDgwNDA4MDM5NDA0OTg3ODQwMDg5Nzc3ODQ2MTUxNTI1NzM5MjYyMzkiLCIyMTQ1MDA0MTMwODY4NDgwMjY2NzM2NzQ4NTE0MzQzOTMwNjQ2ODk0NzQyNDg3NTE5MDExNDcxODM4OTYxOTE4NzA1MDY3MjI2ODYyIl0sWyIyNzEzNTY2NzMxMzI1NDMxMTM3NTU0MDkzOTMwMTkxODEzOTgyMjQzNDc5NDg1MzE2NDE4OTI4MDg0ODQ1NDcyMDMyNjgxODUzNzIzIiwiNTM2OTAxNTI3NTU0NDUzMDcxNDkzMDg4MTAyOTU4NTYzNjczNTQ2NTIyODgxODIwMjIzMTc2ODM2ODEwNTU5Nzk4OTI0OTIzMjE3MiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTQ1NTMwMDk3MDQ1NTQyMzExNjI0ODA0ODYwMDIyMTI3ODkzNDY2ODA4ODg1NjMyMDIxODEwOTEzNTQ5MTA3Mzg4MzUyNTc1NjQzMiIsIjQ4NDkzNjE1OTA0NzY5MjY0MTQ0OTUwNTQ0ODY0MzYwMTM4NTE4NDQ2MTA3Njc2NzIwNDU3NDgyODA0MDM1NTM3NTM0MjIzNTE3NDMiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiMTE5NDAzMjUyNjkwMjY3NDE2MzUzODE3MDczMjQ4NTQ0MTY2OTYwMjM2NzkxMTQ4NTg3MTA3NjQ3ODc1MzcyNzY0MDA1MTU0MzMyNzUiLCIxMjcyMDE3MzYyOTQ1OTE3NTk4OTk1NjQ0NDAyNzgxNjY4NDk4NTMxNzg2NTk2ODgxMzYxNzU3MTUzMjc1Mjk5NDkwMTAyOTI2NDI1MSIsIjAiLCIwIiwiMiIsIjIiLCIyNTE5MTY0MTYzNDg1Mzg3NTIwNzAxODM4MTI5MDQwOTMxNzg2MDE1MTU1MTMzNjEzMzU5NzI2NzA2MTcxNTY0MzYwMzA5NjA2NSIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcwMjk5NDYyMCIsIjIxOTU3ODYxNzA2NDU0MDAxNjIzNDE2MTY0MDM3NTc1NTg2NTQxMiIsIjAiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEyMzQ1Il19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6d3V3NXR5ZFo3QUFkM2Vmd0VxUHBybnFqaU5IUjI0anFydVNQS21WMVYiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOm11bWJhaTp3em9rdlo2a01vb2NLSnVTYmZ0ZFp4VEQ2cXZheUdwSmIzbTRGVlh0aCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjI4MTE4MTE2Nzc2MDQ4NDMxMTIyNjMzMTAwMDYxNDAzODQwMTM0NDU4Mzg0NDczMDg2MzA0NDM1ODA5NjQ5MjUzMTYyMDM4Mjg0NjMiLCI5OTU1ODI3MDU2NTc1NTE4OTAwMTI0MzgzMzUzNjM5OTA0NTk2NTAwNzgyNTYyMTY3NDI5MTg3NDg2MjQxODg4NjA2ODc2NTgzNjk5IiwiMSJdLCJwaV9iIjpbWyI2NjAyNjEwMjM1MjA1Nzk4NTkyMDE5MzI5NDYyMjU5MzYxMjcyNTc3MzU0NDQzMjM5NTYyNjAwOTM4ODUxMjUzOTA3NDY1MDA4MDEyIiwiMTA2NDExMTEyMTMxMDY0MzY2ODIzNTU5NjQwMDkyOTQ2NDUyNDA0NDA5MTQ0MDAxMTgxNTUxNDc3MzQxMjg3MzEzODA4MjQwNzQ0OTYiXSxbIjIwNzQzNzUzMTczNjg3NTI5MTAzNzI5MjM3NTI4NzE3NTU3OTczNjcwMzAxMjg0Njc3ODYwNjkwOTEzOTIzMzk0MDE5ODU0MDU5MTUxIiwiMTg4OTA4NzQ0MzQ0NTQ5NDQ1NTU4NzU3ODAwNjQ4OTc5MDA5NjYwMzI3MjYyNjcxMjE2ODg3MjcxNzQ0ODY0MDM1MzEwNDYyNTU1MjYiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjQ0NzA3ODg1NDE1MjI2ODE4NDQzNDA1MzI3Mjk0ODY2OTIxNTAyNTE0MjIyNzU3MTMzNTQ4MTg4MjkyOTQzMjk4NzcyNTIwODExMTIiLCI5NTIyOTU5NjYwODM4MDAyMTQxMjI0Mzk2NzY5OTA0Nzc2OTE3MzE2NDQ4MDUyMTgwMTgyMjkyNjQ1MTk3Mjg2NDIxMDE1NTkzMDE2IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTY4MjI1NDY5ODg5NDU4MzA1OTE0ODQxNDkwMTc1MjgwMDkzNTU1MDE1MDcxMzI5Nzg3Mzc1NjQxNDMxMjYyNTA5MjA4MDY1IiwiMTc2MzA5NjUwNDQ4OTkwNzM1NzYwOTEwNzE5ODMwMDYzMTE0NTk0MjQ0NDE3MDQxNzA0MzU4NTQzMzM2NDYyNzAyOTkzNTA2ODc4MjkiLCIwIl19';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
