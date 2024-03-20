import { Verifier } from '@lib/auth/auth';
import { testOpts, resolvers } from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  AuthorizationRequestMessage,
  cacheLoader,
  CircuitId,
  ProofType
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
              allowedIssuers: [
                'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
              ],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: { documentType: { $eq: 99 } },
              proofType: ProofType.BJJSignature,
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
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
                '16259159015885704203972860572159615143955018856040187471443250070675076694830',
                '9936261134972021495913066861635092844201384322741097016561225846815554727861',
                '1'
              ],
              pi_b: [
                [
                  '13274307415608622554787983733075359594805362696573187221363487029527021649751',
                  '6770083709194565352752538013885988394082029538687547975296275830191977093579'
                ],
                [
                  '9858564313568500515580682604962916226991978376542020052463904057033098942989',
                  '13481074478476721746530420758311031367861669381777251718356676850384797753756'
                ],
                ['1', '0']
              ],
              pi_c: [
                '8149221637512194456411857416264300795155888057920064325736883074311578592724',
                '16109585571689383482058996181597945116005469364555566560159598173964374245998',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '21575127216236248869702276246037557119007466180301957762196593786733007362',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '0',
              '0',
              '0',
              '1',
              '84239',
              '25198543381200665770805816046271594885604002445105767653616878167826895362',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1710949149',
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
              '25198543381200665770805816046271594885604002445105767653616878167826895362',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qD58KvD3mPB1H1dZKhDPRhEd3aE1Fdx3iGd5VjcHq',
      to: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
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
                'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
              ],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: { ZKPexperiance: { $eq: true } },
              proofType: ProofType.Iden3SparseMerkleTreeProof,
              type: 'KYCEmployee'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
    };

    const message: AuthorizationResponseMessage = {
      id: 'ac381820-21af-499a-8c5d-8f01fca9783c',
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
                '3861193683666781975306242203140068346756283860682260416444665826971771307548',
                '21810894358036153056319810051635175931407878645189526517430393009315784695000',
                '1'
              ],
              pi_b: [
                [
                  '18298965671920870484411439834774874943637171740999661387337056943427101377004',
                  '3258146086436440871190787989125169755873616628531313710472823132022824092498'
                ],
                [
                  '8827991569608995396514322600532414912786284032230818679651315512397940335503',
                  '16062431852624907726401854149167559679027469110872523439460150345436579952148'
                ],
                ['1', '0']
              ],
              pi_c: [
                '10876640267586617362267882068785812826867213950790000254336613394780553351750',
                '17775411727021189595749368764576250038182277003123950451468780261229798413075',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '21575127216236248869702276246037557119007466180301957762196593786733007362',
              '10316494485353306028292038000082940935171221819379372920844877797885116437287',
              '0',
              '0',
              '0',
              '2',
              '84239',
              '25198543381200665770805816046271594885604002445105767653616878167826895362',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1710948584',
              '219578617064540016234161640375755865412',
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
              '1',
              '25198543381200665770805816046271594885604002445105767653616878167826895362',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qD58KvD3mPB1H1dZKhDPRhEd3aE1Fdx3iGd5VjcHq',
      to: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
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
              proofType: ProofType.BJJSignature,
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
              proofType: ProofType.Iden3SparseMerkleTreeProof,
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
      from: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
    };

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImYxZDc5N2NiLTZlMWItNGRhMS1hMDkwLTU5MmNkNDg4OTk0YyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZTViNTg0Ny1iNDc5LTQ0OTktOTBlZS01ZmU0ODI2YTViZGQiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNhZ2UiLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVYzLWJldGEuMSIsInByb29mIjp7InBpX2EiOlsiMTEwMzA1MTc3MzAyMTU4NTk4NTc2OTI1MTM3ODk1MTc5MTUyMzQwNjYxODczNTY3MTM1NTk3NzMzMTE0Nzk3NTYzNzkxNTM3MTM3NTMiLCIyMDIwMjQwNDc4MjU2MTExODkwODE2ODI2NjI5NzUzNDUzMzczMzc0OTA3NTk1ODQ5NDQ5ODk5ODAwMzM0OTMyNTg4NzE2MTMzODI0NyIsIjEiXSwicGlfYiI6W1siMTA4NDkzOTMzNjY2NTQwMzEyNzM4MzU1MDMwODU0NzEwNjI3ODIxNzE4NjM2NjY4MDQxMTEyMTMzMDAxNzA1MDA4NDg3OTcyOTY1MTEiLCI1NDQzMDAyMTA1ODM1NTkzODc5OTU0Nzg5MTY3MDU3MzAwMTcxMDA5MDk4NDk4MTEyMjA3NDQ5MzA3OTA5NTIyNzQ4OTM1MDc1MzUiXSxbIjgyNjE2MzA1Mzc2MDIzMzk0OTkxOTg3NDc3NzQwNTcxNTE3NTAzMzc2Njc3NTM0NjI0MjY0NDQ3OTEwMTkyNjA0NjUzNDMyOTYzMDAiLCIxNDE5MTczMzU2ODE0NDk1NTg4MzY5ODgwMTAyODk3NzkyODQ4MDIxMTQ2MzM3MTM5NTkxOTExNjg0NjI4NjA0OTQyMDY5MzYzMDkyNiJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNDAzMDIwMDE1MDYyMjEwMzcxNjY2ODQ4MDAyNjQ0MTQwODIzNTcxMzA0MDU4NTgzNzYxNzk4OTY2NzY3MjgxMzg5MjM4MjcwNTg0MyIsIjY2NjQzNDQxNzI5NzM2MDA4MjgxMjU3MDc0NTIzNDY0MDQzNzI3MjUyNDQ4MjIzMzUzMzY1MjYyMTMyMzY5Njg3NTA2NTAzMDUyNzMiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMCIsIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3MzYyIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjUxOTkwMjE2MDUxODIxNDQ2MTk3OTkyMTk2Mzg1NjY4NDA0MzU0NTA1Njg2OTIzMjE1NzkxMTk2OTkxOTIxNTE4Nzc1NDI2ODY3NzgiLCIwIiwiMCIsIjEiLCIxIiwiMjUxOTg1NDMzODEyMDA2NjU3NzA4MDU4MTYwNDYyNzE1OTQ4ODU2MDQwMDI0NDUxMDU3Njc2NTM2MTY4NzgxNjc4MjY4OTUzNjIiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MTA5NTE1ODUiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIwIiwiMyIsIjEiLCI5OSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTM2MiIsIjAiXX0seyJpZCI6MiwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5VjMtYmV0YS4xIiwicHJvb2YiOnsicGlfYSI6WyIyMDkzNzA5ODY5NzQyNTM1NDEwOTUwMTIzNTQ4NzAzNzA5Mjg4MDMxMDY4MTgwNTM0MDkwNDA2OTc0MDE5NjQ2NzE0NTg5ODAwNDk5NCIsIjg4NDcyMjUxNjcxNzE1NjMzMTIxMzUwNDM1MDg2NDE1MzExMDIzMzQ0ODY1MDI2Nzg0ODE0NzUzNjg2NzkxMTQ5MzQwNDQ1MTc5OTMiLCIxIl0sInBpX2IiOltbIjIwODEwNDA4Njg2MzMxNTcxNzgzNzk5MDQ2NzA5NTQ4ODY5OTcwMDYyNDczNjUyNzI5ODczMjcwOTMwNDYwNzI4NjkwOTMwMjAyMjk2IiwiMTU0NzMzMjQ3NjgzMDYwMDEzOTIwNTc0ODQwNDUxMjI5NDQ5MjAzMDA0NDEyMjU2NTM3ODQ1MzEzNzE3Mzc4OTE2Mzc4MjI4NTM2MjYiXSxbIjExMjEwMjc4MzM2NTkzMzk5NTg4NTgyMDg1MzMxMTI0MzY0NTAyMzAzOTk5NzkzMzE3NDczNjM3NTE4ODY1NjMwMTg4ODY5MjE3MzY3IiwiNDMxNjA1OTY2OTU0MjI2NDAxNDcwMDcyMTc4NjI5MDU5NTYzNTQxODg1NDc1NTkwNzA2MTAyODMwODY2NDk4NzU4NTQxODU3MzM4NyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiOTA5ODIyMzAzMDg5NDQ1NDEzNTczNDcxMzAzMjczMDk2Njk1MjUxNzE0MzkyMjg5OTEzMjI2MDA4MDMyODYwMDY4MTAwOTA1MzA3MSIsIjY4NTg0ODUzMTI2MTM5MDY0NjYxMzQwNjU4MTk5ODgyMDU5MjM3OTI1NTM0NDgyODYzOTcxODU0NjY1MDA0ODk0MjY0NzAwMjY3OTkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3MzYyIiwiMjAzNjE4NDYwMjk0NzgyNjcyOTI5MTU5MDI3Mjg4OTA1NjQyMTIwMzU1MjIzMjY5NzcyNzA5Mzg0Njc5NTQ3MDMxMDkxNjY2NzE1ODYiLCI0OTcxMTE0NTE5NDIzMTMwNDUzMjk3MTk1NTU3NjIyNDQ4MzYxOTUzNzc2ODYxNTU0OTM5MzAzMTg1NDAwMzM3OTk1NjM3MDM3NTciLCI4Mjg1NzA4ODgxNzM3MDE3MTM3MDM4MzYxNzc4NzY2ODQ2NTk0ODkyODI1NjQ3MTcwMzI1MjMwMDUwNzQ1ODg2NzE0NTMwNDM3ODA3IiwiMCIsIjIiLCIyIiwiMjUxOTg1NDMzODEyMDA2NjU3NzA4MDU4MTYwNDYyNzE1OTQ4ODU2MDQwMDI0NDUxMDU3Njc2NTM2MTY4NzgxNjc4MjY4OTUzNjIiLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MTA5NTE1ODkiLCIyMTk1Nzg2MTcwNjQ1NDAwMTYyMzQxNjE2NDAzNzU3NTU4NjU0MTIiLCIxMjk2MzUxNzU4MjY5MDYxMTczMzE3MTA1MDQxOTY4MDY3MDc3NDUxOTE0Mzg2MDg2MjIyOTMxNTE2MTk5MTk0OTU5ODY5NDYzODgyIiwiMCIsIjEiLCIxNzAyMjUyODAwMDAwMDAwMDAwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjI1MTk4NTQzMzgxMjAwNjY1NzcwODA1ODE2MDQ2MjcxNTk0ODg1NjA0MDAyNDQ1MTA1NzY3NjUzNjE2ODc4MTY3ODI2ODk1MzYyIiwiMTIzNDUiXX1dfSwiZnJvbSI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFENThLdkQzbVBCMUgxZFpLaERQUmhFZDNhRTFGZHgzaUdkNVZqY0hxIiwidG8iOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSHdvTVZnRjIyb3pZZnM0Z1hpQzhycjZTM3NCQ3IyV1NRd2tSVGZCMyJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjczNDY1NzI2NDg1NDQ5NTk1NzM5NTQzMTE1NTYyNzcxNDMyMjk5NTMwMTY2MDY4MzgwNjQ5MDY2ODEzMzUyMDc3MTcxNTE2MTkyMzAiLCI4Mzk4ODc3NDExNTMxNTkxNDA4NTA2OTE1NTY1OTAyODU1OTU0ODMwNDE0NTAwNjA5MjA3Nzg2NDk0ODg2NzIzODExODIyMzAxNDk1IiwiMSJdLCJwaV9iIjpbWyIxMDYyODY4ODQ3ODQyMjUwNDI3MjA5MDMzNDg1NDg3NTgxMjIwMzgyMDM2NTUyNzkzNzc0ODg2OTIwMzE5Mzc3Mjg0ODk2NDU5MzkwNiIsIjE3MDYwNzMxNzkwMzQ2MjM1OTU3NDgzNzQyODA2NTQyNzQwNDY2OTc2MDEzNTYxNzcwMDg4Mjg3NzM1NjQ5NjE1MjUyODUwNzYyNzYwIl0sWyI3NjA2ODc3ODg2NzUxMDI5MDQ1MTU3NTc1OTg2MjIwNTc2NTg3MTg0MDAyNTU3Nzc4NDc4OTgyNjQ0ODg4NTk2NTE1Njk4MTgwMzUzIiwiMTc4MDU3MDAwNzc2NTg1OTU1MDM4MDQwMTc0NzQ2MDI1NTE0NTQ4Nzc4NzgwNDcyODYwNTEwNTQ4NzU3ODkyMzk2NDMyNTc4MjM0NTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjI1MTQzNjUwMDgzNjU1OTcyMjI5OTMwMzQ3NzMxMTY0MjM5NDc3NDk3NDUyMTI4ODEyMTMwNzMwNDUxNTM3ODE3MjYwMjAzMTc4NDAiLCIxNDAyNTIwNjM1ODQ3MTUwMjA2NTg1MjE2NDUwMzE1NDAwNjEwMTgzMzUzMTA5MDE5MjcxMDUzMTM5Nzc3Mzc2NzExNjkxMDMxNTYxMCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzM2MiIsIjE5Mzg0MTc4MzExNDAyNzMyNzk1NDY1NTMwMjM5Mjk0ODI0MjE2NjcwNjYzOTg4MzYxOTI4MDIyNTU1NzE1OTc4MzgwNjY3Njc3MTk0IiwiMCJdfQ';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
