import { v4 as uuidv4 } from 'uuid';

import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  FSCircuitStorage,
  KMS,
  NativeProver,
  PROTOCOL_CONSTANTS,
  PackageManager,
  ZeroKnowledgeProofRequest
} from '@0xpolygonid/js-sdk';
import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import {
  createAuthorizationRequest,
  createAuthorizationRequestWithMessage,
  Verifier
} from '@lib/auth/auth';
import { Circuits } from '@lib/circuits/registry';
import path from 'path';
import { resolveDIDDocument, resolvers, schemaLoader, testOpts } from './mocks';

describe('auth tests', () => {
  const connectionString = process.env.IPFS_URL ?? 'https://ipfs.io';
  it('createAuthorizationRequest', () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const request: AuthorizationRequestMessage = createAuthorizationRequest(
      'kyc age verification',
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.from).toEqual(sender);

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQueryMTPV2',
      query: {
        allowedIssuers: ['1195GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLN9'],
        type: 'KYCAgeCredential',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        credentialSubject: {
          birthday: {
            $lt: 20000101
          }
        }
      }
    };
    request.body.scope.push(proofRequest);
    expect(request.body.scope.length).toEqual(1);
  });

  it('TestVerifyMessageWithoutProof', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const userId = 'did:iden3:polygon:amoy:x7Z95VkUuyo6mqraJw2VGwCfqTzdqhM1RVjRHzcpK';
    const callback = 'https://test.com/callback';
    const msg = 'message to sign';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      'kyc verification',
      msg,
      sender,
      callback
    );

    const response: AuthorizationResponseMessage = {
      id: uuidv4(),
      thid: request.thid,
      typ: request.typ,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      from: userId,
      to: sender,
      body: {
        message: request.body.message,
        scope: []
      }
    };

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      suite: {
        prover: new NativeProver(new FSCircuitStorage({ dirname: '' })),
        circuitStorage: new FSCircuitStorage({ dirname: '../' }),
        packageManager: new PackageManager(),
        documentLoader: schemaLoader
      }
    });

    await expect(verifier.verifyAuthResponse(response, request)).resolves.not.toThrow();
  });

  it('TestVerifyWithAtomicMTPProof', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const reason = 'test';
    const message = 'message to sign';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      message,
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);

    request.thid = '3bfc628a-6d16-4af7-8358-59656ca30600';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQueryMTPV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {
            $lt: 20010101
          }
        }
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).toEqual(1);

    const response: AuthorizationResponseMessage = {
      id: 'd61ca0e1-0fb4-42e1-9baf-10926d76588a',
      typ: PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '3bfc628a-6d16-4af7-8358-59656ca30600',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: 'credentialAtomicQueryMTPV2',
            proof: {
              pi_a: [
                '10193646151489765961716165294209441914505373340739978345545023009943374940812',
                '19540734080723747303959563086264670275414339236530195261122226272390746855937',
                '1'
              ],
              pi_b: [
                [
                  '19467942677882193293944841488842174190120571613164887280488852508969862343027',
                  '17106577273687108884214556012243492970215151434611531033321585163414364507509'
                ],
                [
                  '14498015884038973042346029647348006632739743736155378028992421520463893750183',
                  '19621104134440461747561213754446927179909482545004438474015524348062312609080'
                ],
                ['1', '0']
              ],
              pi_c: [
                '14006417320092906277546140755451080235060132073017953616831608713184292562687',
                '15061888463009562171895687986245706187439910096872145065899377525706148091513',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '21575127216236248869702276246037557119007466180301957762196593786733007617',
              '1',
              '25198543381200665770805816046271594885604002445105767653616878167826895617',
              '18537029360774351903277257040237420954645495647417042860442609334172554965092',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1712132038',
              '74977327600848231385663280181476307657',
              '0',
              '20376033832371109177683048456014525905119173674985843915445634726167450989630',
              '0',
              '2',
              '20010101',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:amoy:x7Z95VkUuyo6mqraJw2VGwCfqTzdqhM1RVjRHzcpK',
      to: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'
    };
    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });
    await expect(verifier.verifyAuthResponse(response, request, testOpts)).resolves.not.toThrow();
  });

  it('TestVerifyWithAtomicSigProofNonMerklized', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const reason = 'test';
    const message = 'message to sign';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      message,
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);

    request.thid = 'cbeb7e95-49a6-4107-ad5d-33de4620a2c7';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQuerySigV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {
            $lt: 20010101
          }
        }
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).toEqual(1);

    const response: AuthorizationResponseMessage = {
      id: 'fe05a780-3a91-4a12-84bd-a23223004543',
      typ: PROTOCOL_CONSTANTS.MediaType.ZKPMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: 'cbeb7e95-49a6-4107-ad5d-33de4620a2c7',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 1,
            circuitId: 'credentialAtomicQuerySigV2',
            proof: {
              pi_a: [
                '3978283874506757525802957933408570785578432271724288548246348383068810207211',
                '3839462864594627131752113404967812699538444256660443277198360774263348025078',
                '1'
              ],
              pi_b: [
                [
                  '1362896848909471153554522290024953846910293534485680267453780104481811422290',
                  '15020898560978280120037685310228488598606735402262450207703916904657862338124'
                ],
                [
                  '21332978512889427960726931487036095435728978762819963806724151119728932608790',
                  '21196976187509848930911656208458284240239739037067667132440783059540157723036'
                ],
                ['1', '0']
              ],
              pi_c: [
                '20396313416829218018504461507621482120133611229332817627860821702949693461370',
                '10644256358167652530995066552061972678660124036948547117328217950416688452505',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '21575127216236248869702276246037557119007466180301957762196593786733007617',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1',
              '25198543381200665770805816046271594885604002445105767653616878167826895617',
              '1',
              '4487386332479489158003597844990487984925471813907462483907054425759564175341',
              '1712132869',
              '198285726510688200335207273836123338699',
              '1',
              '0',
              '2',
              '2',
              '20010101',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0',
              '0'
            ]
          }
        ]
      },
      from: 'did:iden3:polygon:amoy:x7Z95VkUuyo6mqraJw2VGwCfqTzdqhM1RVjRHzcpK',
      to: 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX'
    };

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });
    await expect(verifier.verifyAuthResponse(response, request, testOpts)).resolves.not.toThrow();
  });

  it('TestVerifyJWZ', async () => {
    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      ipfsNodeURL: connectionString
    });

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImZlMDVhNzgwLTNhOTEtNGExMi04NGJkLWEyMzIyMzAwNDU0MyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJjYmViN2U5NS00OWE2LTQxMDctYWQ1ZC0zM2RlNDYyMGEyYzciLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIzOTc4MjgzODc0NTA2NzU3NTI1ODAyOTU3OTMzNDA4NTcwNzg1NTc4NDMyMjcxNzI0Mjg4NTQ4MjQ2MzQ4MzgzMDY4ODEwMjA3MjExIiwiMzgzOTQ2Mjg2NDU5NDYyNzEzMTc1MjExMzQwNDk2NzgxMjY5OTUzODQ0NDI1NjY2MDQ0MzI3NzE5ODM2MDc3NDI2MzM0ODAyNTA3OCIsIjEiXSwicGlfYiI6W1siMTM2Mjg5Njg0ODkwOTQ3MTE1MzU1NDUyMjI5MDAyNDk1Mzg0NjkxMDI5MzUzNDQ4NTY4MDI2NzQ1Mzc4MDEwNDQ4MTgxMTQyMjI5MCIsIjE1MDIwODk4NTYwOTc4MjgwMTIwMDM3Njg1MzEwMjI4NDg4NTk4NjA2NzM1NDAyMjYyNDUwMjA3NzAzOTE2OTA0NjU3ODYyMzM4MTI0Il0sWyIyMTMzMjk3ODUxMjg4OTQyNzk2MDcyNjkzMTQ4NzAzNjA5NTQzNTcyODk3ODc2MjgxOTk2MzgwNjcyNDE1MTExOTcyODkzMjYwODc5MCIsIjIxMTk2OTc2MTg3NTA5ODQ4OTMwOTExNjU2MjA4NDU4Mjg0MjQwMjM5NzM5MDM3MDY3NjY3MTMyNDQwNzgzMDU5NTQwMTU3NzIzMDM2Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIyMDM5NjMxMzQxNjgyOTIxODAxODUwNDQ2MTUwNzYyMTQ4MjEyMDEzMzYxMTIyOTMzMjgxNzYyNzg2MDgyMTcwMjk0OTY5MzQ2MTM3MCIsIjEwNjQ0MjU2MzU4MTY3NjUyNTMwOTk1MDY2NTUyMDYxOTcyNjc4NjYwMTI0MDM2OTQ4NTQ3MTE3MzI4MjE3OTUwNDE2Njg4NDUyNTA1IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjAiLCIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxIiwiMjUxOTg1NDMzODEyMDA2NjU3NzA4MDU4MTYwNDYyNzE1OTQ4ODU2MDQwMDI0NDUxMDU3Njc2NTM2MTY4NzgxNjc4MjY4OTU2MTciLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MTIxMzI4NjkiLCIxOTgyODU3MjY1MTA2ODgyMDAzMzUyMDcyNzM4MzYxMjMzMzg2OTkiLCIxIiwiMCIsIjIiLCIyIiwiMjAwMTAxMDEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eDdaOTVWa1V1eW82bXFyYUp3MlZHd0NmcVR6ZHFoTTFSVmpSSHpjcEsiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eENScDc1RGdBZFM2M1c2NWZtWEh6NnA5RHdkb251UlU5ZTQ2RGlmaFgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjI1MjczODcwMjMxMzM0MjQzMTg2Njk5NzcxNzcwNDY4NjU0MjAxNjY1NDE5ODE1Mjk2NzQ2MTA0OTM4MjQ3NTQ2OTYwNjkzODE4NjciLCIyMDM4ODUxNDU3ODM4MDUwMjk5MjQ1NzYyNjQ0NDcyNDkyNDkyMDA5NTM1OTQzMzg4NTI0NTM2ODk0ODY1MjUzMzExNDk2MzMxMjkxNyIsIjEiXSwicGlfYiI6W1siMTc4NTk2NzQ2NjQzNzk2NzY3NzYyNDY0Njk3MzU5NzczMjczMjQwODU0MTg4ODI5NzA4NjA0MTk3NTE5OTE4ODQ1NTYyOTU1NzIwMjMiLCI5NzgzMzQ5MTc2NDc1MDg3MTQ2NDI1OTk0MDY5MjQzNjI0NDc5NTA4Nzg3OTMxNzgxOTUxMjg5MTEwNDI4OTYwNjIyMDAyMzUyNTk3Il0sWyI4MTc5NTMwMzQ0NjA4MzYzNjEzMzgxMDIxODkxNDczODk3Mzk0MTAzMjEyMDYzNTUxNDY0MTQzNjE3Njc3NDE1NzMzOTU3NzYxNDQ4IiwiODE1MDM4MDM2NjA1MzI2NzIxMTc3NzIwNTE0Mzk4Mzc2NjIwMTY5Nzk1NTEzMzc5NjMwNjc4NDYyNDM4ODM5MTcyODA4MTU2NDcwMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNzY1ODM4ODQ5MzI5NDk2MDA0MjM4ODI4MzE0NjA0MTU2MjYxMzA3OTM1NTU3NzE2NjYxMjQyNTY2Nzk5OTc4Njg5OTE5MzY3NDA0NCIsIjM2ODM4MzQ5Mzk5MTI1NDU5MTQ0NTM3MzMyMzk1NzY5NjExNjQ3MzM1NDUyMjIwNTYzNDc3MDQ1NDAyMTk0NTg5NTM2NTQ0NjU5ODEiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NzUxMjcyMTYyMzYyNDg4Njk3MDIyNzYyNDYwMzc1NTcxMTkwMDc0NjYxODAzMDE5NTc3NjIxOTY1OTM3ODY3MzMwMDc2MTciLCIyMTE4MDA4Mzc4ODU0NDUxNTYwODUyMDQ2Mzg0MjQyOTAwMTY5OTI1ODEyNzA3NjkyMTE4NzU4OTEwNDQwMDQyNDUzMTQ3NDE3NjA2MyIsIjAiXX0';

    await expect(verifier.verifyJWZ(token)).resolves.not.toThrow();
  });

  it('TestFullVerify', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const reason = 'age verification';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      'message to sign',
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQuerySigV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCCountryOfResidenceCredential',
        credentialSubject: {
          countryCode: {
            $nin: [840, 120, 340, 509]
          }
        }
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).toEqual(1);

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });
    request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
    request.thid = '92567472-76d9-499a-8c1f-daae9d105346'; // because it's used in the response

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImE3M2ZkMmZhLTUwNGItNDBmNi04NWQ1LTgzOTJiMjVlZDMwOCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI5MjU2NzQ3Mi03NmQ5LTQ5OWEtOGMxZi1kYWFlOWQxMDUzNDYiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIxMDAwNzM4NzY5MzEzNDE4MzEyNTIyMTIxNDE3Nzg2MjA5MzA5MDM4NzQxMDUwODgzNTgzNjU1ODY3ODA3OTk0NDQwNjY1MzQ5ODczNCIsIjIxMzg3NTM1OTg3MTM5MTUxOTE3MjMyMDM4NDI5OTYwOTAzOTU2Mzk2MTE4NzA5NDMxNzI5MjA1MzAxNjAyODUzMDAyMjQzMzQ5OSIsIjEiXSwicGlfYiI6W1siMTMwNDg3MDAwNTExMTE1NzY2MzIyOTg3NDQ2OTExNjQ0MDI1MDc5NDYwNTI0MjI5NzQzNTYzMDkzNTY1NzgxNjY4OTQyNTQyOTM0MDYiLCIyMTE2NDU4MTY2NjU0MTI0OTY3NTA3ODU5MzI4MDQ1ODMzNzUyNjQ0MjIyODg5MzA1NjU0OTY3NjA5OTQxMTk5OTM3NTQ1MTQ2NTQ2MiJdLFsiMTg4OTk4NDE2NDA2NjYzOTMzMDU2ODg5MTk5OTU2MTgyNDc1MzkyOTYwNzIyODI2Mjc4NjU0NzA3MzY5Njk0OTgxOTc2NzM5ODk0ODAiLCI2NDY1MzEyMTE5Njk1NjM2NTkyNDc0ODU2ODYwNDIzMDAxOTk1OTY0MjMwMzIxMjM1NDYyODA3ODU5NDA2NDUzMzY2MDQyNDQ5NDI5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI5MjA2MjE4NDE3MDI4MDU4NTk4MjQ2MzM4Mzg3NDAyNjYzMDg2OTk5ODA2NTQwNTU0MjYxOTIzMzA2NDA3OTM2Mzg2MTQ5MjMwNjI1IiwiOTM4NjQzNjU0NTMxOTA0MjYxOTM2NDEyNzk2MDI2NjI2MDEzNjk4NTgzOTA3MzMwNzk3NzU1MzE2NTM1NTgzMjQwMzg3NDUwNzk3NSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1NzUxMjcyMTYyMzYyNDg4Njk3MDIyNzYyNDYwMzc1NTcxMTkwMDc0NjYxODAzMDE5NTc3NjIxOTY1OTM3ODY3MzMwMDc2MTciLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMSIsIjI1MTk4NTQzMzgxMjAwNjY1NzcwODA1ODE2MDQ2MjcxNTk0ODg1NjA0MDAyNDQ1MTA1NzY3NjUzNjE2ODc4MTY3ODI2ODk1NjE3IiwiMSIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxNzEyMTQxNTM4IiwiMjAxMTM0NzEzNzU0Mjc5MjM1MTE3MzczMjM2ODQxNTA2MzQ0Mjg1IiwiMCIsIjE3MDAyNDM3MTE5NDM0NjE4NzgzNTQ1Njk0NjMzMDM4NTM3MzgwNzI2MzM5OTk0MjQ0Njg0MzQ4OTEzODQ0OTIzNDIyNDcwODA2ODQ0IiwiMCIsIjUiLCI4NDAiLCIxMjAiLCIzNDAiLCI1MDkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eDdaOTVWa1V1eW82bXFyYUp3MlZHd0NmcVR6ZHFoTTFSVmpSSHpjcEsiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eENScDc1RGdBZFM2M1c2NWZtWEh6NnA5RHdkb251UlU5ZTQ2RGlmaFgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjM1NDUzODM0MTk2MjM1ODA0MzM1OTgzMzQzNDUwMTY3MTI1MzIxODkyMjk3ODI2NjE0NjUzODgwNjEzNzc1NDk3MDU5MzAyMDE2NjgiLCI2MjU2MjkxMzM5MDgyMTg4MjIwOTkzMTU3MzQ3Mzg3OTgzODYyODMwNjY3ODA3ODQzOTcyMjQ2MzUzODM0MzIyNDk2ODIzMTYxNTQ3IiwiMSJdLCJwaV9iIjpbWyIxMDg2MjU0MjMzMDc1OTc2NDEzMTA4NjEwNTM3Njg5Nzk0NTAwMTU2NzUxMDE2OTE0MjYxNjIwMTk1MDM4OTcyNzgzMTAxNDEwMzY0NiIsIjE4NzgyMTA1NDk3OTE1NDEwODk1MjQ5NzAxMzk2OTM2NzU1NzczMzk2MzEzMDQxMzk4NzM1NTI0OTQ0Mzk0NjY5MDQ1NzQzMTIyODcyIl0sWyIxNTgyNTk1MTA3MDQ5ODQzMDg4NTQwNTAxODcwMzY1MzU2OTIxMTk5MDAxMDE5MDc0NDI2MzQyODY2MjAxNTEyMDk1MDE3MTg1MDM3NyIsIjIwNTc2NjgxNDU1MjA5OTAyMjA3ODIzODUzNTM4Mjc4OTI5NTYwNDI5NjQ4NTUyOTA1NjExMzA5Mzg2MTc0MDg1NjEzNDU0MDg5MjEyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI0NDc4NTA3ODQ0MzY0NjI3OTIzNzgzMjU5OTAyNDYyNjExNjI2ODM4OTYwOTkxNTUzMzIzMDgyNDk3MzA2MzMzMzc3MDI5MTQzMzM2IiwiMTc1NDU4MDkxODU3MjMwNTQyNzcyMzIxODkzNzQzNjY2Nzk2NDEzNDUzMzI1OTYyNzY2NDg0NjkyOTQwMDg2ODg0NzU0MzMyNjc1OTQiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1NzUxMjcyMTYyMzYyNDg4Njk3MDIyNzYyNDYwMzc1NTcxMTkwMDc0NjYxODAzMDE5NTc3NjIxOTY1OTM3ODY3MzMwMDc2MTciLCIyNDk0OTAwMzcxMzUyMjUzNjExNDU5NDQ4NDc5MTQ2NTM2NTQ2MDM5NjMyODc3MDAyNDU1ODg3OTMxNDUwNjQ4MDU2MzkyNDMwNDM5IiwiMCJdfQ';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });

  it('TestFullVerify JWS', async () => {
    const token =
      'eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUjUmVjb3ZlcnkyMDIwIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJpZCI6IjJjOGQ5NzQ3LTQ0MTAtNGU5My1iZjg0LTRlYTNjZmY4MmY0MCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJ0aGlkIjoiN2YzOGExOTMtMDkxOC00YTQ4LTlmYWMtMzZhZGZkYjhiNTQyIiwiYm9keSI6eyJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIxMzI3Njk4Nzc5MjQ5MjM0OTA2MDcxMDc3NTEyOTUxMjYxNzY1NjMzODcxMDkxMzE3NDA0NzE0NTcyMDY4Mjk4NzU0MzUwNjY3NDY0IiwiMjA1NDcyOTI1MzQ0MDgxNzA4NDQwODc3MzY2MDQ0OTYyNjQ3MzI2NjUxNDkxMDEzMzMxNzk3NTg5NTAwMjM0NTgwMjA1Njg5NzMzNTYiLCIxIl0sInBpX2IiOltbIjcyNTI1MDEyNjE5ODM1NTYwMjM1NjA3MzI1MjIzODk2MjIxMDY4MTA5OTUxNzkxNjI0MjY2NzcyNDM2MjQwNTQ0Mzc2Nzc1ODI4MCIsIjgyNDU2MTQzMTExNjUzNTUyNzcyNTgyNTg1NTA0MTI5MTUzNjAzNTc2MjEyMDY5OTA0Mjk3NTE3ODk2NTgwNTI1ODY0Mjc2NjgyMDMiXSxbIjg0MjA4OTI3MTI5OTMyMTU5OTU3NjkwMDQ3MzU2Njc5MzY3MDk4MzY5MTY4MzU4MDM2Njc2NjI1NzQxMTcyNjEzNjI2OTgxMzI1MjkiLCIxMDgyOTQzMjI5MDkyODY3MjM1NjAzNjExMTgxNjE4NTQ0MDU3NTgwMDI1NDQzODAyMzUzNTA3MzUzNTY1ODMzOTE0MzMzODAzNDAyNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTIwNTc1NzM1NDQ2Mzc1NDA1MzE2MjIxNDc2NDg2NjE0MDc1NzM1MzY2MjU0MjM0MzY1ODE0MTk2OTY3NzYwOTMxOTY5Nzc5OTg2MzkiLCIxNTIwMzMwMjIxNjcyOTEzOTcwNjQyNjcyMzc5Mzk5Mjk0MjI5NjY1NTU0NDA4MTEwODkzMTE2MjIwMTQxOTcxNzI0MjU4NTQzOTg2NSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjgwMTg1ODg4MjE0NzE5Mzk2MjQ3MTE0MjE5MjIwNzkzOTU0NTE1MDc3NTQzNzU5Nzg0MDgyMzA1MjQ3OTI3ODY4NjI5OTc1MDMiLCIxNDE5MzMwNDc0NzUwMTMzMTE4MTgwOTcxNTkxMjQ4NzIzNjUyNzAwMzkyNTA4MjEwNjc1MjM3Njc5NjA5OTg5MDIwMTkyODE4NTY5MCIsIjEiLCIyMjk0MjU5NDE1NjI2NjY2NTQyNjYxMzQ2Mjc3MTcyNTMyNzMxNDM4MjY0NzQyNjk1OTA0NDg2MzQ0Njg2NjYxMzAwMzc1MTkzOCIsIjEiLCIzMTY5NjEyMzY4MDg3OTA1MzQyNzg2NTE0MDk5NDQ5Mjk3NDA0MzgzODc0MzcxMzU2OTI0ODI4MDgyMTQzNjExOTUzNjIxODU5NzU5IiwiMTY4NzQzMzc0OCIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjIiLCIyIiwiMjAwMDAxMDEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFMUHF2YXlOUXo5VEEycjVWUHhVdWdvRjE4dGVHVTU4M3pKODU5d2Z5In0.bWc2ECABj7nvHatD8AXWNJM2VtfhkIjNwz5BBIK9zBMsP0-UWLEWdAWcosiLkYoL0KWwZpgEOrPPepl6T5gC-AA';
    const sender = 'did:polygonid:polygon:mumbai:2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy';
    const callback = 'https://test.com/callback';
    const reason = 'reason';
    const request: AuthorizationRequestMessage = createAuthorizationRequest(
      reason,
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);
    request.id = '4f3549b-0c9d-47f8-968c-c9b0c10b8847';
    request.thid = '1f3549b-0c9d-47f8-968c-c9b0c10b8847';
    request.typ = PROTOCOL_CONSTANTS.MediaType.SignedMessage;
    request.type = PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_REQUEST_MESSAGE_TYPE;
    request.to = 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQuerySigV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {
            $lt: 20000101
          }
        }
      }
    };
    request.body.scope.push(proofRequest);

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      documentLoader: schemaLoader,
      circuitsDir: path.join(__dirname, './testdata'),
      didDocumentResolver: resolveDIDDocument
    });
    verifier.setupJWSPacker(new KMS(), resolveDIDDocument);

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });

  it('registry: get existing circuit', () => {
    const type = Circuits.getCircuitPubSignals('authV2');
    const instance = new type([
      '19229084873704550357232887142774605442297337229176579229011342091594174977',
      '6110517768249559238193477435454792024732173865488900270849624328650765691494',
      '1243904711429961858774220647610724273798918457991486031567244100767259239747'
    ]) as AuthPubSignalsV2;

    expect(type).not.toBeNull();
    expect(instance).not.toBeNull();
    expect(instance.verifyQuery).not.toBeNull();
    expect(instance.userId.string()).toEqual('x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29');
    expect(instance.challenge.toString()).toEqual(
      '6110517768249559238193477435454792024732173865488900270849624328650765691494'
    );
    // TODO(illia-korotia): why Hash type doesn't implement `toString()` method?
    expect(instance.pubSignals.GISTRoot.string()).toEqual(
      '1243904711429961858774220647610724273798918457991486031567244100767259239747'
    );
  });

  it('verify jwz with selective disclosure', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const reason = 'age verification';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      'message to sign',
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQuerySigV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCAgeCredential',
        credentialSubject: {
          birthday: {}
        }
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).toEqual(1);

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });
    request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
    request.thid = '87f9abf5-26cd-4cda-9b8c-b05e562f23fa'; // because it's used in the response

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjkyZjE4OGUzLWU2N2UtNGMyZC05NWEzLTBiM2JmNGVhYTdhNyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI4N2Y5YWJmNS0yNmNkLTRjZGEtOWI4Yy1iMDVlNTYyZjIzZmEiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwiQHR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vaWRlbjMvY2xhaW0tc2NoZW1hLXZvY2FiL21haW4vc2NoZW1hcy9qc29uLWxkL2t5Yy12NC5qc29ubGQiXSwiQHR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkB0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNH19fSwicHJvb2YiOnsicGlfYSI6WyI5OTcxNDc2NDA5MTYxMDE0NDIxODE1MjYxNzM2MTY3NzY5NjY0ODE5NTc2ODgzOTcxMDA1OTU5Mzk0MjI1ODg1MzM2MzUzMjUwMDIzIiwiNDgwMzg0NTYzMTE5NTIwNzA3NjMwMTY1MTgwNTc3MjE4ODA5NTExMTQ2MDMyMjc3Njc3NjI1NDUzNjg0NTE1Njg1NDM0MTMwNzQ1OCIsIjEiXSwicGlfYiI6W1siMTUxODM3Mjc2MDEzMTU5MDIzNjk5MDIzNDEzNzA5MDgwNzgxNTI0OTM4MTM5NjQwMDIxODQyNTQyNzE2NDQ1MDA2NzY5NzQwMjY1MiIsIjE5NzE0MTI0OTYwMzQ4NTI5MDg4MTY4Mzg2OTA1NDIwOTU2MDA2NDgyMjIwMTczNjMyOTMzOTc2MDQyMDY2MzA4MDc3NDUzMjgwMDQ1Il0sWyIxMTM1NDY1MzIwOTM1MDQ3MzUwODA1MTY4NzAyNzY2MDM3MzU0OTQyMzIxNTgzMDM1MDA3MDc1OTU4NjgyNTcwMTczODQwNzQzNTI5MCIsIjU5NjY0MDY2NjczNTIzNjQxODExNDM1MDUyNzk2MjYyMzk3ODc0MjY3MjI2MzAzNjE1ODgxNzk4MTgwMTM3MzUyOTM1NjIwNDg2MDkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjIwMDA0NzQ3ODU4MzE2NzYyODgzMTg3MzQxMjYxMjc5MDQ2MzE2NDYxMTQzNDMwNzQ1MzMwMTcyNzc5NDM1ODQ3MDI4MzUxMzU4MjgxIiwiMTU3MzkxNDEwNDA4MTEyODU4NzA0MDAwNzg1MjAyMTQ0ODE5NjIzOTcxODAwNTgyNjM2MTYzNzM0MTI5MjYwMDcyMzU1MTkzMzc1NzYiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3NjE3IiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjEiLCIyNTE5ODU0MzM4MTIwMDY2NTc3MDgwNTgxNjA0NjI3MTU5NDg4NTYwNDAwMjQ0NTEwNTc2NzY1MzYxNjg3ODE2NzgyNjg5NTYxNyIsIjEiLCI0NDg3Mzg2MzMyNDc5NDg5MTU4MDAzNTk3ODQ0OTkwNDg3OTg0OTI1NDcxODEzOTA3NDYyNDgzOTA3MDU0NDI1NzU5NTY0MTc1MzQxIiwiMTcxMjE0MjcyNiIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjAiLCIxIiwiMTk5NjA0MjQiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eDdaOTVWa1V1eW82bXFyYUp3MlZHd0NmcVR6ZHFoTTFSVmpSSHpjcEsiLCJ0byI6ImRpZDppZGVuMzpwb2x5Z29uOmFtb3k6eENScDc1RGdBZFM2M1c2NWZtWEh6NnA5RHdkb251UlU5ZTQ2RGlmaFgifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjE0NTU3OTk2MTMzNTQ1NjUxNjIzNDIxNTYzOTQ4MTc3OTQ5NTA0NzY1MzUyNzMwOTE0NTkwODQ2NzEyNTU3NjU0MjQwNTc2OTEzNDE5IiwiMTMzMjM0MjI5NTE2NTIxNTE1ODk1NDQzMjc1MTEwMTUxMTYxMzY0NzM2Nzg1NDY0NzIxNTM0MjE2MTI2MDMwMzkyNjAxMTMzNjM5NTIiLCIxIl0sInBpX2IiOltbIjUwNTgyMDY3NjkzMDYyMDU1OTkzNzk0NDAwODIwNTI4NTIyNzA2Nzg3NzE3MTA2NDMxNDA1MTYxNjQzNjA0MDA2ODEyNDQ3NTM1OCIsIjE2MzI3Njg1MDYxMjgzMDM4ODEyODgxODYxNjAxNjc3NzY1Mjk1Njk2NDkxMzg3Mjc5Njg2MzUyNTAzMDA2NDAxNTI2Mzc1OTM1NDA1Il0sWyIxMTMyNzU0NjkwODI1NjMzMDQwNjM1OTg4MDg3MDU0OTAyNTg2MTE5NjU4NjUyMzQ4MDM5OTQ3ODU0MTIwNzEyNjUzMjExMTkzODc2IiwiMTUzNDA0MDMwOTIzMjI0MjMwMjk2MTQ0MzE5OTk3OTkzMjk0MDk3MDY0Nzk1MDg5NDMzMzUyNTQxNzA4OTA5NTczMjQ0NjgwMDg5OTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjY0NTUyODc1Mzk4OTMyODcxNDA0OTI2MDU1NTMzMzg3MDYyNjgxODkyOTMxMTQ4MDg5NTI3MzgxNTA3ODYwNTUyMDM3NTA1NDA2MjQiLCIxNjI1MTQ3NDg2ODgxNzExNzI5ODE3MjI3MjMzNjA1NTU2MDIzMjMxMjQ3NzkxMzM1NjMxMDcwMjgzNTA0OTY1ODA3MzUxNjcwMzQwNyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjI3MjE3NDkzNTA2NTU1MjQ1NzQ0MjU1OTQxNTY2NDEwMzUzOTcyNjIyNDc1NjAwOTY5NDkzODYzODgwNTM2NTI5MTkyMjYxNjUzMzciLCIwIl19';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });

  it('test verify empty credential subject', async () => {
    const sender = 'did:iden3:polygon:amoy:xCRp75DgAdS63W65fmXHz6p9DwdonuRU9e46DifhX';
    const callback = 'https://test.com/callback';
    const reason = 'age verification';
    const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
      reason,
      'message to sign',
      sender,
      callback
    );
    expect(request.body.scope.length).toEqual(0);
    expect(request.body.callbackUrl).toEqual(callback);
    expect(request.body.reason).toEqual(reason);
    expect(request.from).toEqual(sender);

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 1,
      circuitId: 'credentialAtomicQuerySigV2',
      query: {
        allowedIssuers: ['*'],
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
        type: 'KYCAgeCredential'
      }
    };
    request.body.scope.push(proofRequest);

    expect(request.body.scope.length).toEqual(1);

    const verifier = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata'),
      documentLoader: schemaLoader
    });
    request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
    request.thid = '4594d6a8-660d-4747-8147-0e06a2fc29ed'; // because it's used in the response

    const token =
      'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjZhNDAwN2Y2LWI0NjQtNDAwMy1iZDU0LTFhYjMzZjk0OTBiMyIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI0NTk0ZDZhOC02NjBkLTQ3NDctODE0Ny0wZTA2YTJmYzI5ZWQiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIxMjIzNzg3NjE3OTk1MDEwMDE5NDM1MDE5NzY5NDQ0Nzk0MzYxNjY5NDYwNzM1ODA3NDQ3MzE5MTIwNzA0OTExOTIyNjY4MTIxMTQxMSIsIjEwNjYzNzQ5MDA1NzMyNzcyMDE0MTE1NDM5ODkyMjE0Mjg4NTcxOTgyMDY0MjU5NjgxNTI1MDkwMDI0NzM5Njk1NjczOTg4MDEyMTE2IiwiMSJdLCJwaV9iIjpbWyIxNzIyOTI5MzMwMDc0NDI4MjkxNTczNzQyNTU5MDY2NzUyOTU3NDM2Mjg2ODA5MTUxNzA1MTE5ODYyMzgyNTQ0MjM4MDAzMTg2NzQ0NCIsIjE1NzQ2MjU1ODUxODUwNjAwMzYzOTQ5ODY0NDYxMzA2NDQ5NjcyNDYxMzIxMTI0MzUwOTIwMTE4OTkwNDIyODQ2NTg5Mzk3NzY0NzYyIl0sWyIyMDk5OTk1MTQ1NzA1NjU3ODQ1MjQ3NzE5MTM2NjAwMjIyNTA1Mjc0NTM5NjI4NTIwODg0MzA5MzMwMTQxODg2MTEyNjE3MzA0NTEwNSIsIjIwNzI3Mzg3MTM4OTYzNzQzODUxNzU4MjE4MzAwNTk2NzkxMjk0ODE2Mjk0NDE1NzYzODk1ODI5MTkwNTc5Nzk2MjA1OTE4ODA0NjA4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxMzA5NjIxMDgxMjc0OTY0NTU1MDcwOTE2Nzg0ODE2OTkwNjgxNzkyMjc1MDcxNDY4NzAxMDEzNjMzMTM3NTQwODExMzUyNjc1MzM5MCIsIjE5ODYxMDU3MDkxNjA1Nzg5MjI4ODg3Mjk0NTIyMTE4NTcxMjQzMzk2NjkzNTU1MzIyNzc1NjM0Nzg1Mjg1MTM1MDkwMTg4ODIyODQ1IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjQ0ODczODYzMzI0Nzk0ODkxNTgwMDM1OTc4NDQ5OTA0ODc5ODQ5MjU0NzE4MTM5MDc0NjI0ODM5MDcwNTQ0MjU3NTk1NjQxNzUzNDEiLCIxIiwiMjUxOTg1NDMzODEyMDA2NjU3NzA4MDU4MTYwNDYyNzE1OTQ4ODU2MDQwMDI0NDUxMDU3Njc2NTM2MTY4NzgxNjc4MjY4OTU2MTciLCIxIiwiNDQ4NzM4NjMzMjQ3OTQ4OTE1ODAwMzU5Nzg0NDk5MDQ4Nzk4NDkyNTQ3MTgxMzkwNzQ2MjQ4MzkwNzA1NDQyNTc1OTU2NDE3NTM0MSIsIjE3MTIxNDM0NTYiLCIyNjc4MzE1MjE5MjI1NTgwMjcyMDYwODIzOTAwNDMzMjE3OTY5NDQiLCIwIiwiNDc5MjEzMDA3OTQ2MjY4MTE2NTQyODUxMTIwMTI1MzIzNTg1MDAxNTY0ODM1Mjg4MzI0MDU3NzMxNTAyNjQ3Nzc4MDQ5MzExMDY3NSIsIjAiLCIxIiwiODUxMDE4ODUzODc0MTk3NzM0NjU4OTk2MzE3NTUwNjI5Mjc0NjgzMTYxOTQ1NzUzNTU3NjcwMjM1ODAwNzU3NDAxMTI3MTUxMzM4MiIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4N1o5NVZrVXV5bzZtcXJhSncyVkd3Q2ZxVHpkcWhNMVJWalJIemNwSyIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4Q1JwNzVEZ0FkUzYzVzY1Zm1YSHo2cDlEd2RvbnVSVTllNDZEaWZoWCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjE3OTI3MTQzMDU2OTU0NDA2NjY3MzAwNDg5MjI1MjAyMjAxNDc2MDI5MTYzMzM4ODc2Nzc0NzkyMDkzNjEyNTU4ODU3MTg3NzUzMzQwIiwiMTk2Mzg2ODc5MTgzNzcxNzcwMjQzNTYzNjI3MTE0MzU2MTEyMjI3Njk5ODMwOTc0MzEzNzI2ODMwMzA0OTg3NjIzMjQ3NjQ1MDI0MzgiLCIxIl0sInBpX2IiOltbIjkzMjY1NTUwODAwOTQxOTUxMTkyOTI5NjY5OTEyNzQ4MzgwMzE4MzY4ODM1Njg1NTM5Nzk3ODk1NTgxODUwNzg5OTcyMjQyMDA2OTgiLCIyMTM3OTc4MjQwNTcwNjY1MDQzNzgzNzU1MDk1MDk0MTIxMTQyMzg0OTE1MzY1NTk5ODU2ODQ0ODQ5OTM5MDYwNzI2OTAxMDk0NTcyNSJdLFsiMTE2NzU1MzUxMzMxODMzNTM4MTUzMDk3MDgyNTUwNzkxMDYxMDAwNzE1ODc0NTIzMzcxNzI0MTg2MjEyOTg0MzE5MzIwODkzOTc3NDciLCIxNjgzOTQzODM0NTI3OTU1NzkzNDg4NjAzNzg4NzYwNDc4MDY5NTEzODc5NDA5NzM5NTgyMjg4MDM5NjI2MjY4MDQxNjEzOTY4MTg3NCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTIzNjAxMzc4NDg4MjU1OTE1NTIwMDU0MDMwMDk5NjY0MDcwMzQ4MjIzMjI5MDY2MTQ2OTY4NzEzMzMxNTk2ODMwMjg2NTA1NjU1NjUiLCIxMTkxNjIxNTk5NTY4MDU1MzAwMjU2MTE4MjI5NDUxODkzOTczMDAyMTg1NjUyOTcxMTc1ODc3OTcwNDcyOTcxMTUyNDc0NzIzNjMxMiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTU3NTEyNzIxNjIzNjI0ODg2OTcwMjI3NjI0NjAzNzU1NzExOTAwNzQ2NjE4MDMwMTk1Nzc2MjE5NjU5Mzc4NjczMzAwNzYxNyIsIjIxODc3MjU0ODI3Njk4MjM0MDYzMzgwOTk3NjE2MzI0NTM2MzgwMDAxNzkwOTEzMzMyNTQ1OTk4MzkzMzMxMjY2MzAwMjI1NDUwNDYzIiwiMCJdfQ';

    await expect(verifier.fullVerify(token, request, testOpts)).resolves.not.toThrow();
  });
});
