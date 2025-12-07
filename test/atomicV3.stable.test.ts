import { Verifier } from '@lib/auth/auth';
import { testOpts, resolvers, getTestDataPath } from './mocks';
import { AuthorizationRequestMessage, AuthorizationResponseMessage } from '@0xpolygonid/js-sdk';
import { it, describe, expect } from 'vitest';
import { Token } from '@iden3/js-jwz';

describe('stable circuits with dynamic circuits selection', () => {
  const authRequest: AuthorizationRequestMessage = {
    id: '29df4cbf-3fa7-4094-bd2f-c125111a5930',
    typ: 'application/iden3comm-plain-json',
    type: 'https://iden3-communication.io/authorization/1.0/request',
    thid: '29df4cbf-3fa7-4094-bd2f-c125111a5930',
    body: {
      accept: ['iden3comm/v1;env=application/iden3-zkp-json;circuitId=authV3'],
      callbackUrl: 'http://localhost:8080/callback?id=1234442-123123-123123',
      reason: 'reason',
      message: 'message',
      scope: [
        {
          id: 2,
          circuitId: 'linkedMultiQuery10',
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
          },
          params: {
            nullifierSessionId: '12345',
            verifierDid: {
              method: 'iden3',
              id: 'polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX',
              idStrings: ['polygon', 'amoy', 'xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'],
              params: [],
              path: '',
              pathSegments: [],
              query: '',
              fragment: ''
            }
          }
        }
      ]
    },
    from: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'
  } as AuthorizationRequestMessage;

  it('TestVerifyV3MessageWithSigProof_NonMerklized', async () => {
    const message: AuthorizationResponseMessage = {
      id: 'd42144d5-a34c-40c2-accc-75cfe432cd2b',
      typ: 'application/iden3-zkp-json',
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '29df4cbf-3fa7-4094-bd2f-c125111a5930',
      body: {
        message: 'message',
        scope: [
          {
            id: 2,
            circuitId: 'linkedMultiQuery3',
            vp: undefined,
            proof: {
              pi_a: [
                '994106614568213848932474864471849092909129135306173172080929808989903385516',
                '17998516922381670107091027985262723693373119784455439809643941833595664289422',
                '1'
              ],
              pi_b: [
                [
                  '15842263367675508503610383786560228143392553926916101526939014588582773896970',
                  '2932049911102963551744501377368452150215209464578111889912277297932164606659'
                ],
                [
                  '20556107859111370379564219586101411354757979942651497031979196804262980194593',
                  '8584689252293854808582743759273380783873046804218474230648914100342183787713'
                ],
                ['1', '0']
              ],
              pi_c: [
                '8323155298327601927302137506186521493131362294423261941986273674760363882321',
                '6011515557219288306339474028731998394435653700080193695498101827962778273749',
                '1'
              ],
              protocol: 'groth16',
              curve: 'bn128'
            },
            pub_signals: [
              '18105787563950103293288405202502009969688717661633745854840717923296594420492',
              '1',
              '0',
              '0',
              '0',
              '15577114799056939633552845531011024672939493492769628285661359711655214561162',
              '16998762965396944782667557741185828136467747762830028217027973617373862301958',
              '9302526208507753799501130128908494673412443631541424409551205277529949662394'
            ]
          },
          {
            id: 3,
            circuitId: 'credentialAtomicQueryV3-16-16-64',
            vp: undefined,
            proof: {
              pi_a: [
                '13480567022205661636403851463301003396049999031614637697629922560690078313677',
                '123059920719176172031832406184406411935643081536536263720076609199873975586',
                '1'
              ],
              pi_b: [
                [
                  '13540254692552012657176391179061794763195039956595674209584134387260351771293',
                  '13014430766012204225061387050223559421047084875274993141898175782732461669774'
                ],
                [
                  '10478702382185300287318670875097208381178099102046747282027729998146279821409',
                  '12533104756606385779798404259878398860128881502370339050173271031967411623877'
                ],
                ['1', '0']
              ],
              pi_c: [
                '20501323041257476423611062816073006146843354292265038305567989571327374882491',
                '14173395171880716681547301718926707059359212272689857520307739110010841348467',
                '1'
              ],
              protocol: 'groth16',
              curve: 'bn128'
            },
            pub_signals: [
              '1',
              '21575127216236248869702276246037557119007466180301957762196593786733007617',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '18105787563950103293288405202502009969688717661633745854840717923296594420492',
              '5113110742163561161681110600858018886440291288962681233429975133916348606521',
              '0',
              '1',
              '3',
              '25198543381200665770805816046271594885604002445105767653616878167826895617',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1764944200',
              '219578617064540016234161640375755865412',
              '1296351758269061173317105041968067077451914386086222931516199194959869463882',
              '0',
              '1',
              '1702252800000000000',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
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
              '25198543381200665770805816046271594885604002445105767653616878167826895617',
              '12345'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:amoy:x7Z95VkUuyo6mqraJw2VGwCfqTzdqhM1RVjRHzcpK',
      to: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'
    } as AuthorizationResponseMessage;

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: getTestDataPath('./testdata')
    });

    await authInstance.verifyAuthResponse(message, authRequest, testOpts);
  });

  it('TestFullVerify - Auth V3-8-32', async () => {
    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: getTestDataPath('./testdata'),
      ipfsNodeURL: process.env.IPFS_URL ?? 'https://ipfs.io'
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYzLTgtMzIiLCJjcml0IjpbImNpcmN1aXRJZCJdLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuMy16a3AtanNvbiJ9.eyJpZCI6ImQ0MjE0NGQ1LWEzNGMtNDBjMi1hY2NjLTc1Y2ZlNDMyY2QyYiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIyOWRmNGNiZi0zZmE3LTQwOTQtYmQyZi1jMTI1MTExYTU5MzAiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIiwic2NvcGUiOlt7ImlkIjoyLCJjaXJjdWl0SWQiOiJsaW5rZWRNdWx0aVF1ZXJ5MyIsInByb29mIjp7InBpX2EiOlsiOTk0MTA2NjE0NTY4MjEzODQ4OTMyNDc0ODY0NDcxODQ5MDkyOTA5MTI5MTM1MzA2MTczMTcyMDgwOTI5ODA4OTg5OTAzMzg1NTE2IiwiMTc5OTg1MTY5MjIzODE2NzAxMDcwOTEwMjc5ODUyNjI3MjM2OTMzNzMxMTk3ODQ0NTU0Mzk4MDk2NDM5NDE4MzM1OTU2NjQyODk0MjIiLCIxIl0sInBpX2IiOltbIjE1ODQyMjYzMzY3Njc1NTA4NTAzNjEwMzgzNzg2NTYwMjI4MTQzMzkyNTUzOTI2OTE2MTAxNTI2OTM5MDE0NTg4NTgyNzczODk2OTcwIiwiMjkzMjA0OTkxMTEwMjk2MzU1MTc0NDUwMTM3NzM2ODQ1MjE1MDIxNTIwOTQ2NDU3ODExMTg4OTkxMjI3NzI5NzkzMjE2NDYwNjY1OSJdLFsiMjA1NTYxMDc4NTkxMTEzNzAzNzk1NjQyMTk1ODYxMDE0MTEzNTQ3NTc5Nzk5NDI2NTE0OTcwMzE5NzkxOTY4MDQyNjI5ODAxOTQ1OTMiLCI4NTg0Njg5MjUyMjkzODU0ODA4NTgyNzQzNzU5MjczMzgwNzgzODczMDQ2ODA0MjE4NDc0MjMwNjQ4OTE0MTAwMzQyMTgzNzg3NzEzIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI4MzIzMTU1Mjk4MzI3NjAxOTI3MzAyMTM3NTA2MTg2NTIxNDkzMTMxMzYyMjk0NDIzMjYxOTQxOTg2MjczNjc0NzYwMzYzODgyMzIxIiwiNjAxMTUxNTU1NzIxOTI4ODMwNjMzOTQ3NDAyODczMTk5ODM5NDQzNTY1MzcwMDA4MDE5MzY5NTQ5ODEwMTgyNzk2Mjc3ODI3Mzc0OSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxODEwNTc4NzU2Mzk1MDEwMzI5MzI4ODQwNTIwMjUwMjAwOTk2OTY4ODcxNzY2MTYzMzc0NTg1NDg0MDcxNzkyMzI5NjU5NDQyMDQ5MiIsIjEiLCIwIiwiMCIsIjAiLCIxNTU3NzExNDc5OTA1NjkzOTYzMzU1Mjg0NTUzMTAxMTAyNDY3MjkzOTQ5MzQ5Mjc2OTYyODI4NTY2MTM1OTcxMTY1NTIxNDU2MTE2MiIsIjE2OTk4NzYyOTY1Mzk2OTQ0NzgyNjY3NTU3NzQxMTg1ODI4MTM2NDY3NzQ3NzYyODMwMDI4MjE3MDI3OTczNjE3MzczODYyMzAxOTU4IiwiOTMwMjUyNjIwODUwNzc1Mzc5OTUwMTEzMDEyODkwODQ5NDY3MzQxMjQ0MzYzMTU0MTQyNDQwOTU1MTIwNTI3NzUyOTk0OTY2MjM5NCJdfSx7ImlkIjozLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlWMy0xNi0xNi02NCIsInByb29mIjp7InBpX2EiOlsiMTM0ODA1NjcwMjIyMDU2NjE2MzY0MDM4NTE0NjMzMDEwMDMzOTYwNDk5OTkwMzE2MTQ2Mzc2OTc2Mjk5MjI1NjA2OTAwNzgzMTM2NzciLCIxMjMwNTk5MjA3MTkxNzYxNzIwMzE4MzI0MDYxODQ0MDY0MTE5MzU2NDMwODE1MzY1MzYyNjM3MjAwNzY2MDkxOTk4NzM5NzU1ODYiLCIxIl0sInBpX2IiOltbIjEzNTQwMjU0NjkyNTUyMDEyNjU3MTc2MzkxMTc5MDYxNzk0NzYzMTk1MDM5OTU2NTk1Njc0MjA5NTg0MTM0Mzg3MjYwMzUxNzcxMjkzIiwiMTMwMTQ0MzA3NjYwMTIyMDQyMjUwNjEzODcwNTAyMjM1NTk0MjEwNDcwODQ4NzUyNzQ5OTMxNDE4OTgxNzU3ODI3MzI0NjE2Njk3NzQiXSxbIjEwNDc4NzAyMzgyMTg1MzAwMjg3MzE4NjcwODc1MDk3MjA4MzgxMTc4MDk5MTAyMDQ2NzQ3MjgyMDI3NzI5OTk4MTQ2Mjc5ODIxNDA5IiwiMTI1MzMxMDQ3NTY2MDYzODU3Nzk3OTg0MDQyNTk4NzgzOTg4NjAxMjg4ODE1MDIzNzAzMzkwNTAxNzMyNzEwMzE5Njc0MTE2MjM4NzciXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjIwNTAxMzIzMDQxMjU3NDc2NDIzNjExMDYyODE2MDczMDA2MTQ2ODQzMzU0MjkyMjY1MDM4MzA1NTY3OTg5NTcxMzI3Mzc0ODgyNDkxIiwiMTQxNzMzOTUxNzE4ODA3MTY2ODE1NDczMDE3MTg5MjY3MDcwNTkzNTkyMTIyNzI2ODk4NTc1MjAzMDc3MzkxMTAwMTA4NDEzNDg0NjciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3NjE3IiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE4MTA1Nzg3NTYzOTUwMTAzMjkzMjg4NDA1MjAyNTAyMDA5OTY5Njg4NzE3NjYxNjMzNzQ1ODU0ODQwNzE3OTIzMjk2NTk0NDIwNDkyIiwiNTExMzExMDc0MjE2MzU2MTE2MTY4MTExMDYwMDg1ODAxODg4NjQ0MDI5MTI4ODk2MjY4MTIzMzQyOTk3NTEzMzkxNjM0ODYwNjUyMSIsIjAiLCIxIiwiMyIsIjI1MTk4NTQzMzgxMjAwNjY1NzcwODA1ODE2MDQ2MjcxNTk0ODg1NjA0MDAyNDQ1MTA1NzY3NjUzNjE2ODc4MTY3ODI2ODk1NjE3IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzY0OTQ0MjAwIiwiMjE5NTc4NjE3MDY0NTQwMDE2MjM0MTYxNjQwMzc1NzU1ODY1NDEyIiwiMTI5NjM1MTc1ODI2OTA2MTE3MzMxNzEwNTA0MTk2ODA2NzA3NzQ1MTkxNDM4NjA4NjIyMjkzMTUxNjE5OTE5NDk1OTg2OTQ2Mzg4MiIsIjAiLCIxIiwiMTcwMjI1MjgwMDAwMDAwMDAwMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjEiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTYxNyIsIjEyMzQ1Il19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95Ong3Wjk1VmtVdXlvNm1xcmFKdzJWR3dDZnFUemRxaE0xUlZqUkh6Y3BLIiwidG8iOiJkaWQ6aWRlbjM6cG9seWdvbjphbW95OnhDUnA3NURnQWRTNjNXNjVmbVhIejZwOUR3ZG9udVJVOWU0NkRpZmhYIn0.eyJwcm9vZiI6eyJwaV9hIjpbIjkzMTY0NDYzMjY4MTA3OTA2MzA3MjEwNDk5NTE5MDY2NzQ5MjM4Mzc1MjAwMzE5ODk5OTEzMzE0MDE2MzU3MjQ4NzUwNDA0NzA5MDMiLCIxOTI4NDQyMDY2MTU0ODc2NjAwNDkwOTgwNzc5MDYwOTA4OTAxMjU1NTEyMjAyMjczNjgzODY2NjUxMTIxNzkxOTM2NTYxMzM1MTg2NSIsIjEiXSwicGlfYiI6W1siMTU3ODczNjM2NzAwNzQ3NTE2MTYwNjgzOTg3NTMwODYxMzYyOTA0Njc5MDU1ODgyNjc2MTY5NjU4MDQ4ODc2NzQ4MDE4MjA0ODczNjMiLCI0OTYyOTYwNjcwNjMxNTA2MjAwODk5NjUyMzI4MTIxMDA3OTYwNjY0NjE5OTcyNTUyNjMyNzE2MTE3NDg1NTQxODcxOTU5MTAxNDEwIl0sWyIxNzk3MDI4MzA0MjEyMTk1ODEyNDU3OTg1MzY5OTU2MDE3ODc1ODYxODQ1OTQ3NTAxOTg0NzAxMDExNzA3NTY4NjY1MTM1MDM4Mzc0MyIsIjgxNDQ2ODUxNzEzNzYzNjA2MjQxNjM4MzI4ODE4NTYwNzY1MDkzNzA5MDM2NDIyNTc1NzI2NjYzNTE2MzY4MDcxNDcwNDA1Nzg4OTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjQyMDEwMzM3NTIzMjMwMzA4OTI0ODY0NzE3Mzk5NTU4NjU0MDg4OTg0OTAzNjEwOTU2NDU3MjE5NzQwMjc4MTA0NTczODQ1Njg1NjciLCI4MjY0MzA2MzMyNzgxNTIxMzA3MTQ5ODk4MjgyMTE2Mzc1NjA1OTEwODQxMjA2Njg4ODMxODU0ODYyNzYxMTMxMzI4OTcwNTA0NzU0IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3NjE3IiwiMjA5MTE4NTI3OTM5MDU1MjczMTcxNTg0MzQ3OTc0MDMzNTQ0MjU1MDQyNjUwNTgwMDg2OTE1MDE4MDM3MTE1NjU5MTAxMDQ4NTE0MzgiLCIxNzg0OTk4MTcyMDYzNDIxMjgwMjY2NDE4OTkyOTY3MTE0MDc2MjU1NzQ4MzIzNjcwODA5NzcyMzg4NDE3MjY0MTEyNDY5MTIyMjI5OCJdfQ';

    const parsedToken = await Token.parse(token);
    expect(parsedToken.circuitId).toBe('authV3-8-32');

    await expect(verifier.fullVerify(token, authRequest, testOpts)).resolves.not.toThrow();
  });
});
