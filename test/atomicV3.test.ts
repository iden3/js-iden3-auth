import { Verifier } from '@lib/auth/auth';
import { testOpts, resolvers, getTestDataPath } from './mocks';
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
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
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
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
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
      circuitsDir: getTestDataPath('../circuits')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
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
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
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
      circuitsDir: getTestDataPath('../circuits')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('auth with atomicV3 (nullifier, 2 req (merklized and non-merklized))', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7d22275a-b518-45bb-8ee1-85e12abd8532',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: '7d22275a-b518-45bb-8ee1-85e12abd8532',
      body: {
        callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
        reason: 'reason',
        message: 'message',
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
      from: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'
    };

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: getTestDataPath('../circuits'),
      documentLoader: schemaLoader
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjMzYmU1YjE4LWIyYzktNDdmZi1hMTJlLTA0OThhNjdlNDYyYyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJhYzAxZWYyYy04MWNiLTRlMTUtYjYxYS01N2QyMGQ4Mjg4YzIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIiwic2NvcGUiOlt7ImlkIjoxLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy1iZXRhLjEiLCJwcm9vZiI6eyJwaV9hIjpbIjE3NTE0Nzg3Mjc4OTIyMzg4MTIyOTE2MDg1OTk5MjI0NzUxNTMyNTQwNTQ2OTcxNjQ2Nzc5NTQwNTEyOTI1MDQ0MDEzMDAzMzM5NDkwIiwiMjk2NjE1MTY0NjMzODM5Njc4Mzk1NjgyMjM0NjQzOTg0NTU3NjM3OTAxMzEzMzk0MzY3MzczNTY4MDAwOTM2MjQxODcwODg5NjQxMSIsIjEiXSwicGlfYiI6W1siMzY1MDgwMzg5NjQwNDIzMzA4NjczOTM0NjI1MjYzODU5NTMwODcyODI4NzA2OTkzNDAyOTQzMDUzODUyMTE4NzMyOTgwMjEzNDk3IiwiMTg5MTc5ODU3ODMyNzg3NzgyMjQyNDY3NTc5Nzg3NjQ3NzAwMTM4OTM5NjcyNjIyNzc5MTk1Mzc0MDA0MzU3MjAyMDA3MDEyMTMyODgiXSxbIjcyOTM4NzI2MDYxOTg1MTgwODQ4NTk1MDk3NTExNDkyMTcyNTYyMDI4ODk2MjMzMDc0MzgzODY3OTM3MDMwNTQyODE1NDAyNDkwNjIiLCI3ODcyNjYxMTIzMzA1NTczMzA5MjUzNzgxNTgzMjc1MDk2MTg2NDc0Mzg5MzU3NTcyMzE2MDIxMDQ1ODAwODM4Mjk5NTE5MzAzODMzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyIyMDc3MDU1OTk5NTYwMzQ4NzM4NjYyMTE3NzE2MTM2MzI5Njc3NjM1MDg1MTA5MzYyOTM1OTQ5OTQxMjUyMzQyNTIxODg3MzYxOTg3NyIsIjE4MzU1NDY5OTQ3MTExNTUyNjUzNjY5ODI5NDU4MzE0NTMzNTI4OTM2MDEzMDQzNzc2OTAzMzIyOTI4NTE2NzY0MTUyODk5Nzc5NTIyIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNTIxMjMyMDY1MTQyMDg0MzcyMjQzMDg1NzU5MzI1NDY5MzA5NTU2OTI2NzY5Mjg5MzM1OTM1Mjc1NDA0NjExNjgyNjM2MDQyNzA3MiIsIjAiLCIwIiwiMSIsIjEiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTYxNyIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcyNTkwOTEyNSIsIjE5ODI4NTcyNjUxMDY4ODIwMDMzNTIwNzI3MzgzNjEyMzMzODY5OSIsIjAiLCIzIiwiMSIsIjk5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMSIsIjI1MTk4NTQzMzgxMjAwNjY1NzcwODA1ODE2MDQ2MjcxNTk0ODg1NjA0MDAyNDQ1MTA1NzY3NjUzNjE2ODc4MTY3ODI2ODk1NjE3IiwiMCJdfSx7ImlkIjoyLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy1iZXRhLjEiLCJwcm9vZiI6eyJwaV9hIjpbIjIwMjM3Nzg4NTQ0MTgzMzIyODk2MjU1MTU4ODQ0NjM4MDI2NDU2NzM5MDEwMzAyNzE2MTMyNjExODgwNDU4NTU1NzY5MjY1NjYxNTYyIiwiMTU1NTYxOTY4NjIyOTk1MDIyOTYyOTE4MDAzNzA5MjE5MjM0NjEzMjAzMDQxMTkxMjkyMTU0NzE2NTM5NDYwMTUxNzg1MjE0ODYzNDEiLCIxIl0sInBpX2IiOltbIjE2NTIwNTExMTM2MjQwODM0MzE4MTg2MDg3MjM4NTQxNDA4NTc2OTE5MTUyNjI1ODExNzY3MTUyMzA4MTI5MzU3MzM5NDQ4MjQ4MTc4IiwiMjU4MTAzNTc2NjU0MTU0NjkwMzg5MzQ1MzI2MDA3MjQxMjI1MzkxNTgxNjEwODY0NDM5MzI4MDkxNzczODQwMTQ2NjUwMTM1NDQ3NyJdLFsiOTM2ODAxODIzNzI1NTc0OTA0OTA0OTUzNzUzNjMwNjg2MDg2NDYzNDI1NTI1OTU0NzQ3NDY1OTUxMjE0NTkwOTU5MDk4ODYwNTkwNSIsIjExNjcxOTMyMTU4MTgxODk2MzgyNjA2NDY0Mzk1NjM3OTMxNjc1MjIzMDE2MDc4NDE5MzY1MzM4MjczODcxNDcwNDA5NDQwNDU2Mzc2Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxODQzODUxMTkzMzEyMTg0ODcyODY5NjU2MjI3NDM3NTc0NTQ0NDU5OTcwOTQ5NDgyNzM5MzY0Mzg3OTkzMjUxODQwOTU5NjU4OTkxNiIsIjE2NDcwMTgwMzE0MDI3NjI2MjUwMjQzMjU3NDYzNjcwMjU3MjQ4NjY0Nzg5MjM1OTMzMTg3NzkzOTg1MDU4MjI4NjQ2MzE0ODUxMzMyIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjMxMTIyOTA2NDMxNTQxMTY4OTg5NzI4MzE2OTg0MzU2MTEwNjYwNTUzOTY0Mjg1MTY1MDIwOTk5ODQ2NTk4MzcwOTAyMjc1NjIzNCIsIjIwMDQ1MzY5OTA0MzIzMzE3ODc1MTYxMjM2NDkzOTE3NzU3ODUyNDc4MDQ0MDQxMjk2NjExNDEwNDc3MTk2MjIzODEwMTE1Nzg0ODAyIiwiNTExMzExMDc0MjE2MzU2MTE2MTY4MTExMDYwMDg1ODAxODg4NjQ0MDI5MTI4ODk2MjY4MTIzMzQyOTk3NTEzMzkxNjM0ODYwNjUyMSIsIjAiLCIyIiwiMiIsIjI1MTk4NTQzMzgxMjAwNjY1NzcwODA1ODE2MDQ2MjcxNTk0ODg1NjA0MDAyNDQ1MTA1NzY3NjUzNjE2ODc4MTY3ODI2ODk1NjE3IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzI1OTA5MTMwIiwiMjE5NTc4NjE3MDY0NTQwMDE2MjM0MTYxNjQwMzc1NzU1ODY1NDEyIiwiMTI5NjM1MTc1ODI2OTA2MTE3MzMxNzEwNTA0MTk2ODA2NzA3NzQ1MTkxNDM4NjA4NjIyMjkzMTUxNjE5OTE5NDk1OTg2OTQ2Mzg4MiIsIjAiLCIxIiwiMTcwMjI1MjgwMDAwMDAwMDAwMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTYxNyIsIjEyMzQ1Il19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95Ong3Wjk1VmtVdXlvNm1xcmFKdzJWR3dDZnFUemRxaE0xUlZqUkh6Y3BLIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95OnhDUnA3NURnQWRTNjNXNjVmbVhIejZwOUR3ZG9udVJVOWU0NkRpZmhYIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjExMTk4MDQ3ODYxNzgxNjYyNTc2NzM4NzA3NDM2NjE3NjY0MTI0MDI2NDA5MzA3Mjk2MjAxNjA3Nzg2MTYzNjM4NzgyMTc2MTkwNTYxIiwiMzM5Njc3MTI2Njg0NjMwNDA5NjIzMjU4OTgxODMxNTc3OTYxMTg1NjY5MzU0NDI5ODU3OTM1NTM1ODQ1NzEyMjA1OTExNjc0MDQ2OSIsIjEiXSwicGlfYiI6W1siMjQ3ODQ1NTExMzM0NjYwOTcwNzU4ODgzODIyMjQ2Mzc4NTU0NjQwOTE0MDIyNjAwMzQ3MDU2NzE1NDU4NjY1NTgzODk1OTE2NDYyNiIsIjkyOTMwMTk0MDA4NDcyNTI0MjMyODk3Njk1NDQ2MTE0NjU4ODE0OTEyNzY3ODA3OTI5ODk2NDc3NzI3MjE1ODIwNzY2NzY2NjUyMTIiXSxbIjM4NTkyMzg1NjUxOTQ3OTQ4NjUxNTM3NDU0NDUzNzA3NzYyMjM2NjgwNjQ4MTk1Nzk4MjczMjkyMTc5MjM2NDk4MDg0NTU5OTEzMjYiLCIyMTg3MjI4OTA2MDg0MTE4MDM3NDI3NTAwMTA5Mjg4OTY2NzQ2NzUyMzkxMDI2NTIyMDQxODY1NDA3MDM0MDI0MDAxNDA4NDQxNjIxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiODgxODAyMDA2NzQ5NDc5NDI5Njg2MDk3NjAyODE2MjU1OTg0OTM1Nzg1MjcwOTM2NTU5ODI2OTI5NDAxNzEzODEyMDY0MDk2NTg2NCIsIjE3OTcyNDU1NzY5MzUwNzkxMTE3OTQwMjA3NjM3NjU0ODYxOTA4ODk5MjAwMzI3NjA3ODUzNzY4NjYxMTE1ODIyOTAwNzU0NDk3OTQzIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3NjE3IiwiMjQ3MDc1MTE5NDk3NTU4Njk5NzU5ODQzMTI5NzMyMzc4NTAwNzIwMDE4NTk2NTMzNTc1ODc1OTA2MTgxNjM1NDgyNjc1MjY5MTA5MSIsIjE3ODQ5OTgxNzIwNjM0MjEyODAyNjY0MTg5OTI5NjcxMTQwNzYyNTU3NDgzMjM2NzA4MDk3NzIzODg0MTcyNjQxMTI0NjkxMjIyMjk4Il19';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized_exists', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        scope: [
          {
            id: 1711522489,
            circuitId: CircuitId.AtomicQueryV3,

            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
              credentialSubject: { birthday: { $exists: true } },
              proofType: ProofType.BJJSignature,
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT'
    };

    const message: AuthorizationResponseMessage = {
      id: 'ac381820-21af-499a-8c5d-8f01fca9783c',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        scope: [
          {
            id: 1711522489,
            circuitId: CircuitId.AtomicQueryV3,
            proof: {
              pi_a: [
                '21800211430949703449644722551376257237362982820810967048456391134029879678806',
                '21613713430915613066339120095996323766151016451049155252578200709882864737789',
                '1'
              ],
              pi_b: [
                [
                  '661072511254964853872611502929686343046899584048079678556280335611662815845',
                  '2273089975406654115307642615483414515773518585010287695430027009913825128768'
                ],
                [
                  '17444892701184321994625361553850698475151625663824663639633423947771970343321',
                  '15630676073412856608625380437792507729110631716538445053251013755584497527789'
                ],
                ['1', '0']
              ],
              pi_c: [
                '21296780288267664754328313860061774394253634460478952036284913832000895592194',
                '6946412759922081597032874175095790261523599890928317338700002333834382713410',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '29164643842236980629969889601908506056905540530259492186963618550155186690',
              '13483594486393726782589954979757194488582220051583949915340451442108840786819',
              '0',
              '0',
              '0',
              '1',
              '1711522489',
              '20140537885605785819118769494650292165307016100986347572517912906305442306',
              '1',
              '14623770256788200718910247650869365371230778783613615087356654172486552332511',
              '1711522550',
              '267831521922558027206082390043321796944',
              '20376033832371109177683048456014525905119173674985843915445634726167450989630',
              '0',
              '11',
              '1',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
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
              '19077537563018779797836314438360413772747104486842143844867680645228663298',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qE45yJ5i6g1dYPP45KMw38Xbvh8aebPzfXLfxtrhu',
      to: 'did:polygonid:polygon:mumbai:2qH7TstpRRJHXNN4o49Fu9H2Qismku8hQeUxDVrjqT'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: getTestDataPath('../circuits')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized_noop', async () => {
    const request: AuthorizationRequestMessage = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE,
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        scope: [
          {
            id: 1711377832,
            circuitId: CircuitId.AtomicQueryV3,

            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
              proofType: ProofType.BJJSignature,
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
    };

    const message: AuthorizationResponseMessage = {
      id: 'ac381820-21af-499a-8c5d-8f01fca9783c',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        scope: [
          {
            id: 1711377832,
            circuitId: CircuitId.AtomicQueryV3,
            proof: {
              pi_a: [
                '7555135671567273543704218764274850015720432713673229342215169366176898598929',
                '5118059757222184178232295484120895788454978441731084933033870844411500481244',
                '1'
              ],
              pi_b: [
                [
                  '14212250237160868782979223012368501182246698067654154738920528940031235088380',
                  '18217717461197738936131417405953772342169705587070066489162095180660073064671'
                ],
                [
                  '16772018071565641000678496564873785294025025924126602838983639773623869064801',
                  '4936938093592837071503468878843020708039523542423061890804250451547565506589'
                ],
                ['1', '0']
              ],
              pi_c: [
                '4721635046811376766778210935918363175751512711098010569765488285431776823966',
                '20588271981362351104785915980589379197992461314597051622104515944586759543278',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '20156969113212549915290105481651790678263685077956855660838446742358921730',
              '13483594486393726782589954979757194488582220051583949915340451442108840786819',
              '0',
              '0',
              '0',
              '1',
              '1711377832',
              '20140537885605785819118769494650292165307016100986347572517912906305442306',
              '1',
              '20054680232313097776046407964659487432368209966036937175997819086186177614781',
              '1711377852',
              '267831521922558027206082390043321796944',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '19077537563018779797836314438360413772747104486842143844867680645228663298',
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qK9EukpMd6GQy9hfXfX31LUk89rmqX21hYe62LEnW',
      to: 'did:polygonid:polygon:mumbai:2qHwoMVgF22ozYfs4gXiC8rr6S3sBCr2WSQwkRTfB3'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: getTestDataPath('../circuits')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });
});
