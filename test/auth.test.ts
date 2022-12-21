import { AUTHORIZATION_RESPONSE_MESSAGE_TYPE } from '@lib/protocol/constants';
import { v4 as uuidv4 } from 'uuid';

import { getCurveFromName } from 'ffjavascript';
import { FSKeyLoader } from '@lib/loaders/key';
import { ISchemaLoader, UniversalSchemaLoader } from '@lib/loaders/schema';
import { IStateResolver, ResolvedState } from '@lib/state/resolver';
import { AuthPubSignalsV2 } from '@lib/circuits/authV2';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  ZKPRequest,
  ZKPResponse,
} from '@lib/protocol/models';
import {
  createAuthorizationRequest,
  createAuthorizationRequestWithMessage,
  Verifier,
} from '@lib/auth/auth';
import { Circuits } from '@lib/circuits/registry';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

const verificationKeyLoader: FSKeyLoader = new FSKeyLoader('./test/data');
const schemaLoader: ISchemaLoader = new UniversalSchemaLoader('ipfs.io');

class MockResolver implements IStateResolver {
  resolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0,
    };
    return Promise.resolve(t);
  }
  rootResolve(): Promise<ResolvedState> {
    const t: ResolvedState = {
      latest: true,
      state: null,
      genesis: false,
      transitionTimestamp: 0,
    };
    return Promise.resolve(t);
  }
}
const mockStateResolver: MockResolver = new MockResolver();

test('createAuthorizationRequest', () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const request: AuthorizationRequestMessage = createAuthorizationRequest(
    'kyc age verification',
    sender,
    callback,
  );
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.from).toEqual(sender);

  const proofRequest: ZKPRequest = {
    id: 1,
    circuitId: 'credentialAtomicQueryMTPV2',
    query: {
      allowedIssuers: ['1195GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLN9'],
      type: 'KYCAgeCredential',
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      req: {
        birthday: {
          $lt: 20000101,
        },
      },
    },
  };
  request.body.scope.push(proofRequest);
  expect(request.body.scope.length).toEqual(1);
});

test('TestVerifyMessageWithoutProof', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const userId = '119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ';
  const callback = 'https://test.com/callback';
  const msg = 'message to sign';
  const request: AuthorizationRequestMessage =
    createAuthorizationRequestWithMessage(
      'kyc verification',
      msg,
      sender,
      callback,
    );

  const response: AuthorizationResponseMessage = {
    id: uuidv4(),
    thid: request.thid,
    typ: request.typ,
    type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
    from: userId,
    to: sender,
    body: {
      message: request.body.message,
      scope: [],
    },
  };

  const verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('TestVerifyWithAtomicMTPProof', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const userId =
    'did:polygonid:polygon:mumbai:2qNAbfxams2N4enwgBhj7yvPUbDrLwC2bsBZYZCTQR';
  const reason = 'test';
  const message = 'message to sign';
  const request: AuthorizationRequestMessage =
    createAuthorizationRequestWithMessage(reason, message, sender, callback);
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';

  const proofRequest: ZKPRequest = {
    id: 10,
    circuitId: 'credentialAtomicQueryMTPV2',
    query: {
      allowedIssuers: ['*'],
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      type: 'KYCCountryOfResidenceCredential',
      req: {
        countryCode: {
          $nin: [840, 120, 340, 509],
        },
      },
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const mtpProof: ZKPResponse = {
    id: proofRequest.id,
    circuitId: 'credentialAtomicQueryMTPV2',
    proof: {
      pi_a: [
        '9517112492422486418344671523752691163637612305590571624363668885796911150333',
        '8855938450276251202387073646943136306720422603123854769235151758541434807968',
        '1',
      ],
      pi_b: [
        [
          '18880568320884466923930564925565727939067628655227999252296084923782755860476',
          '8724893415197458543695192455798597402395044930214471497778888748319129905479',
        ],
        [
          '9807559381041464075347519433137353143151890330916363861193891037865993320923',
          '6995202980453256069532771522391679223085808426805857698209331232672383046019',
        ],
        ['1', '0'],
      ],
      pi_c: [
        '16453660244095377174525331937765624986258178472608723119429308977591704509298',
        '7523187725705152586426891868747265746542072544935310991409893207335385519512',
        '1',
      ],
      protocol: 'groth16',
      curve: 'bn128',
    },
    pub_signals: [
      '1',
      '25054465935916343733470065977393556898165832783214621882239050035846517250',
      '10',
      '25054465935916343733470065977393556898165832783214621882239050035846517250',
      '7120485770008490579908343167068999806468056401802904713650068500000641772574',
      '1',
      '7120485770008490579908343167068999806468056401802904713650068500000641772574',
      '1671543597',
      '336615423900919464193075592850483704600',
      '0',
      '17002437119434618783545694633038537380726339994244684348913844923422470806844',
      '0',
      '5',
      '840',
      '120',
      '340',
      '509',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
    ],
  };

  const response: AuthorizationResponseMessage = {
    id: uuidv4(),
    thid: request.thid,
    typ: request.typ,
    type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
    from: userId,
    to: sender,
    body: {
      message: request.body.message,
      scope: [mtpProof],
    },
  };

  const verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('TestVerifyJWZ', async () => {
  const verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE2NzY1Mjg4NjY0MTkyNjg4MDU1MTMyMTY2Mjg0OTg0NjE0ODg0MTIzNTg0NTE0NTI0MTU4NzE4MDYxOTYxNjE3OTk2NjUwMzc1NTc0IiwiMTUxMzAxNzA3OTM1MjEzNTM1MzM2NzUyOTg1NTk3OTA3NTU0ODM5MjU4NzExNDY5NTkwMjgzODk5NzQ0MTg1NjEzNjY2NDI3NzA2MjIiLCIxIl0sInBpX2IiOltbIjExOTg5NzQ5NDM1NzA3MzEzNjU4MjUyNzA4OTcyODc1NTgzNzA3OTg1NjQ5NjA4MjM0NDIyOTQ4NzI5MDQ4NDY3NzI0Mjk4NzI5NTI4IiwiMTg3NTYxNTM4OTI1Njc1OTY2NDgwNjY4NzA2Njk3NTg1NTcwMjYxOTE5NjgyNzEwNDI5MTA1NDUwODUwNTg2NzUwOTA1NzEwMTQ0NiJdLFsiOTE4NTY4MjMzNTc4NDgxNTU4NjQ0NTQ5MjMwNzMyNzcyMDM5MzcxNTY2NDMzNTcwMzM2NzE3NDMzMzU4NjU1NjAwNDk0MTE2MjE4NiIsIjE2NDIyNzM3Njc3MzA1MTkyNTc5MDY2ODIwMTgzOTU5MjYxMTc5NDA4Nzc2ODQ2MjcxNjE5MTI5MTMxOTYwNzk0MTI4MDU5NjkxNTI5Il0sWyIxIiwiMCJdXSwicGlfYyI6WyI3OTc3NjIyODQwODYwNzE0NjQwMTE3OTQ0NjU5ODE2Mzk2ODgwODkyMjU4NTIzNjgwMzk2NDE0ODI2Mjc2NDk2NjM1NTIyNTUxNTUzIiwiMjExNTUwNjE3Njk1MDIwMjg5OTEyNzM0NjQyMzgwNjg2MjEwNDc1NTQzMDg4NzkwODc3OTEzMDk0NzU1ODY2NTE0ODIxMDI4NjA5NDIiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIyNjEwOTQwNDcwMDY5NjI4MzE1NDk5ODY1NDUxMjExNzk1MjQyMDUwMzY3NTQ3MTA5NzM5MjYxODc2MjIyMTU0NjU2NTE0MDQ4MSIsIjYxMTA1MTc3NjgyNDk1NTkyMzgxOTM0Nzc0MzU0NTQ3OTIwMjQ3MzIxNzM4NjU0ODg5MDAyNzA4NDk2MjQzMjg2NTA3NjU2OTE0OTQiLCIxMTA5ODkzOTgyMTc2NDU2ODEzMTA4NzY0NTQzMTI5NjUyODkwNzI3NzI1MzcwOTkzNjQ0MzAyOTM3OTU4NzQ3NTgyMTc1OTI1OTQwNiJdfQ';

  await expect(verifier.verifyJWZ(token)).resolves.not.toThrow();
});

test('TestFullVerify', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const reason = 'age verification';
  const msgToSign = 'message to sign';
  const request: AuthorizationRequestMessage =
    createAuthorizationRequestWithMessage(reason, msgToSign, sender, callback);
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  const proofRequest: ZKPRequest = {
    id: 10,
    circuitId: 'credentialAtomicQueryMTPV2',
    query: {
      allowedIssuers: ['*'],
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
      type: 'KYCCountryOfResidenceCredential',
      req: {
        countryCode: {
          $nin: [840, 120, 340, 509],
        },
      },
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.eyJpZCI6IjI3NGI1ODE5LWMxNDctNGExNy1iNGUxLTRmZDJhOWNmNTdhNSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI4NWFjMjc3Yi0xYWZlLTQzY2EtYWNmZC1mOTM5ZTAwODBkZDYiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEwLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFBWMiIsInByb29mIjp7InBpX2EiOlsiOTUxNzExMjQ5MjQyMjQ4NjQxODM0NDY3MTUyMzc1MjY5MTE2MzYzNzYxMjMwNTU5MDU3MTYyNDM2MzY2ODg4NTc5NjkxMTE1MDMzMyIsIjg4NTU5Mzg0NTAyNzYyNTEyMDIzODcwNzM2NDY5NDMxMzYzMDY3MjA0MjI2MDMxMjM4NTQ3NjkyMzUxNTE3NTg1NDE0MzQ4MDc5NjgiLCIxIl0sInBpX2IiOltbIjE4ODgwNTY4MzIwODg0NDY2OTIzOTMwNTY0OTI1NTY1NzI3OTM5MDY3NjI4NjU1MjI3OTk5MjUyMjk2MDg0OTIzNzgyNzU1ODYwNDc2IiwiODcyNDg5MzQxNTE5NzQ1ODU0MzY5NTE5MjQ1NTc5ODU5NzQwMjM5NTA0NDkzMDIxNDQ3MTQ5Nzc3ODg4ODc0ODMxOTEyOTkwNTQ3OSJdLFsiOTgwNzU1OTM4MTA0MTQ2NDA3NTM0NzUxOTQzMzEzNzM1MzE0MzE1MTg5MDMzMDkxNjM2Mzg2MTE5Mzg5MTAzNzg2NTk5MzMyMDkyMyIsIjY5OTUyMDI5ODA0NTMyNTYwNjk1MzI3NzE1MjIzOTE2NzkyMjMwODU4MDg0MjY4MDU4NTc2OTgyMDkzMzEyMzI2NzIzODMwNDYwMTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NDUzNjYwMjQ0MDk1Mzc3MTc0NTI1MzMxOTM3NzY1NjI0OTg2MjU4MTc4NDcyNjA4NzIzMTE5NDI5MzA4OTc3NTkxNzA0NTA5Mjk4IiwiNzUyMzE4NzcyNTcwNTE1MjU4NjQyNjg5MTg2ODc0NzI2NTc0NjU0MjA3MjU0NDkzNTMxMDk5MTQwOTg5MzIwNzMzNTM4NTUxOTUxMiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyNTA1NDQ2NTkzNTkxNjM0MzczMzQ3MDA2NTk3NzM5MzU1Njg5ODE2NTgzMjc4MzIxNDYyMTg4MjIzOTA1MDAzNTg0NjUxNzI1MCIsIjEwIiwiMjUwNTQ0NjU5MzU5MTYzNDM3MzM0NzAwNjU5NzczOTM1NTY4OTgxNjU4MzI3ODMyMTQ2MjE4ODIyMzkwNTAwMzU4NDY1MTcyNTAiLCI3MTIwNDg1NzcwMDA4NDkwNTc5OTA4MzQzMTY3MDY4OTk5ODA2NDY4MDU2NDAxODAyOTA0NzEzNjUwMDY4NTAwMDAwNjQxNzcyNTc0IiwiMSIsIjcxMjA0ODU3NzAwMDg0OTA1Nzk5MDgzNDMxNjcwNjg5OTk4MDY0NjgwNTY0MDE4MDI5MDQ3MTM2NTAwNjg1MDAwMDA2NDE3NzI1NzQiLCIxNjcxNTQzNTk3IiwiMzM2NjE1NDIzOTAwOTE5NDY0MTkzMDc1NTkyODUwNDgzNzA0NjAwIiwiMCIsIjE3MDAyNDM3MTE5NDM0NjE4NzgzNTQ1Njk0NjMzMDM4NTM3MzgwNzI2MzM5OTk0MjQ0Njg0MzQ4OTEzODQ0OTIzNDIyNDcwODA2ODQ0IiwiMCIsIjUiLCI4NDAiLCIxMjAiLCIzNDAiLCI1MDkiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFOQWJmeGFtczJONGVud2dCaGo3eXZQVWJEckx3QzJic0JaWVpDVFFSIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01Ub1IifQ.eyJwcm9vZiI6eyJwaV9hIjpbIjgwMzM1NzQwMzc0MjEyOTIxMDY4Mzk5MjkwMTg5ODA4MzcxMDM3NTY2NTA4MTkyMTgzNjgzODYyOTAxNTY1MzY0MTIyNTY5MjQwOTUiLCI1MjA2ODkzODk0MTg2ODE1Mjg1MzIyNjQ3MDUwOTkyNDk0ODQwNzc1MDUwMTM2MzgwMjYyMjM2MTkyNTIwNzQ2ODY1OTA3OTczNDIyIiwiMSJdLCJwaV9iIjpbWyIyMTQzNzU0OTcxNTU3NzA2MzkzNDM3NTM3ODcyMDQwMzIxMzIzNDExODM5MDQ3NjQyMzI3MDY2NTQxNzUwMDA3ODU2ODg2NDE1NzIzOCIsIjY5MTQ0MjkxMTM0ODEwMDQyODYwODcxOTc3MTI4NjgzNjIzMTcwMTQyMTk2MjA3NDg0NjQ4OTgyMjI1MDU2NjA5MzgyMjQ4NDk4MDciXSxbIjEyMzUwMDk4MjEzMjk2OTM4NTM3Mzk0NTEwODQ0MzAyODM3NTk4MTUyOTQ1NTA5NzExNzk2OTg4MzM0MjAzOTY2NzU2MzY2OTQ1NTA4IiwiMjcwOTE5NDc5NjcyNTEzMzA1ODM4Mzc5MTczMjM2NDIxMjA3MTkyNDg2MTQxMjIyOTU4NjUzNTk3Njc1NTc1MjM4NzQyNjUyNzg0MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTkwMTQ3MzM1MTgwNTE1Nzg1MDk3Nzc4MzQ0ODEwMjg3NzkzODc1NDI0NjAwMjE5MzI3OTk1MTUxNzY4Mzk1NzE2MDI5MDU0ODQyNTIiLCIyMTUwNDg1MzA5MDQ0MTc3MDMzMzA2NDI4NDk3MjY1MDE3NDI2OTc5MjA3OTg1MTY1Mzk3NzczMjc0MjcyMDY2ODExNDAwMjk1OTQ5MCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjI1MDU0NDY1OTM1OTE2MzQzNzMzNDcwMDY1OTc3MzkzNTU2ODk4MTY1ODMyNzgzMjE0NjIxODgyMjM5MDUwMDM1ODQ2NTE3MjUwIiwiODE4ODQ4NTI3MDk2MTY2NzYwMTc3MjQ5OTE2ODMwNzU2MDEyNDYxNzM5MjE3NzcxODQyODUxODg3NjgyNjU4MjAzNzk0NjU4MzI2NCIsIjUzMDQ2ODU5NDU1MjQxNzcyMDgzNDk0NzM3NzcyMzM5NzA2OTY1NTU4MDQ3NDA3MzYxNTg2MDY4MjUxMTY4MDYwODAwNTQ2MDQzODUiXX0';

  await expect(verifier.fullVerify(token, request)).resolves.not.toThrow();
});

test('TestResponseWithEmptyQueryRequest', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const userId =
    'did:polygonid:polygon:mumbai:2qNAbfxams2N4enwgBhj7yvPUbDrLwC2bsBZYZCTQR';
  const reason = 'test';
  const request: AuthorizationRequestMessage = createAuthorizationRequest(
    reason,
    sender,
    callback,
  );
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  const proofRequest: ZKPRequest = {
    id: 10,
    circuitId: 'credentialAtomicQueryMTPV2',
    query: {
      allowedIssuers: ['*'],
      type: 'KYCCountryOfResidenceCredential',
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const mtpProof: ZKPResponse = {
    id: proofRequest.id,
    circuitId: 'credentialAtomicQueryMTPV2',
    proof: {
      pi_a: [
        '9517112492422486418344671523752691163637612305590571624363668885796911150333',
        '8855938450276251202387073646943136306720422603123854769235151758541434807968',
        '1',
      ],
      pi_b: [
        [
          '18880568320884466923930564925565727939067628655227999252296084923782755860476',
          '8724893415197458543695192455798597402395044930214471497778888748319129905479',
        ],
        [
          '9807559381041464075347519433137353143151890330916363861193891037865993320923',
          '6995202980453256069532771522391679223085808426805857698209331232672383046019',
        ],
        ['1', '0'],
      ],
      pi_c: [
        '16453660244095377174525331937765624986258178472608723119429308977591704509298',
        '7523187725705152586426891868747265746542072544935310991409893207335385519512',
        '1',
      ],
      protocol: 'groth16',
      curve: 'bn128',
    },
    pub_signals: [
      '1',
      '25054465935916343733470065977393556898165832783214621882239050035846517250',
      '10',
      '25054465935916343733470065977393556898165832783214621882239050035846517250',
      '7120485770008490579908343167068999806468056401802904713650068500000641772574',
      '1',
      '7120485770008490579908343167068999806468056401802904713650068500000641772574',
      '1671543597',
      '336615423900919464193075592850483704600',
      '0',
      '17002437119434618783545694633038537380726339994244684348913844923422470806844',
      '0',
      '5',
      '840',
      '120',
      '340',
      '509',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
      '0',
    ],
  };

  const response: AuthorizationResponseMessage = {
    id: uuidv4(),
    thid: request.thid,
    typ: request.typ,
    type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
    from: userId,
    to: sender,
    body: {
      message: request.body.message,
      scope: [mtpProof],
    },
  };

  const verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('registry: get existing circuit', () => {
  const type = Circuits.getCircuitPubSignals('authV2');
  const instance = new type([
    '19229084873704550357232887142774605442297337229176579229011342091594174977',
    '6110517768249559238193477435454792024732173865488900270849624328650765691494',
    '1243904711429961858774220647610724273798918457991486031567244100767259239747',
  ]) as AuthPubSignalsV2;

  expect(type).not.toBeNull();
  expect(instance).not.toBeNull();
  expect(instance.verifyQuery).not.toBeNull();
  expect(instance.userId.string()).toEqual(
    'x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29',
  );
  expect(instance.challenge.toString()).toEqual(
    '6110517768249559238193477435454792024732173865488900270849624328650765691494',
  );
  // TODO(illia-korotia): why Hash type doesn't implement `toString()` method?
  expect(instance.gistRoot.string()).toEqual(
    '1243904711429961858774220647610724273798918457991486031567244100767259239747',
  );
});
