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
    rules: {
      query: {
        allowedIssuers: '1195GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLN9',
        type: 'KYCAgeCredential',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        req: {
          birthday: {
            $lt: 20000101,
          },
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
    'did:iden3:polygon:mumbai:x3vgBmSWMecbkxFAvT8waWejmCLmzHcrG56sXbAhB';
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
    rules: {
      query: {
        allowedIssuers: '*',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        type: 'KYCCountryOfResidenceCredential',
        req: {
          countryCode: {
            $nin: [840, 120, 340, 509],
          },
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
        '553107328829552739356143409585452140182890751904479913169932084064672719342',
        '6414164353444149373251860755937247195440148247977996873464801175864488600187',
        '1',
      ],
      pi_b: [
        [
          '1848793935234157552257829088144777701654345181741201635414140644827541802063',
          '2690669073070388025072668654408175248782610232957303774118462170802712453278',
        ],
        [
          '5055095222783166923422204514647227537440069458420869376587492848653363173060',
          '483202060159956789222074171559922542038004267623840366839963428406782614282',
        ],
        ['1', '0'],
      ],
      pi_c: [
        '1629496919538541173933472398151128146708748529834203088117936150271440668414',
        '14513257679897863036989550655794291459834670206310872236326790971807658823114',
        '1',
      ],
      protocol: 'groth16',
      curve: 'bn128',
    },
    pub_signals: [
      '1',
      '26337405203610566029241995866156151469433315212067050574696144339180786177',
      '10',
      '26337405203610566029241995866156151469433315212067050574696144339180786177',
      '21498905153686139720023221743570456290445230580677931307974644282469683226010',
      '21498905153686139720023221743570456290445230580677931307974644282469683226010',
      '1670860707',
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
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.bXltZXNzYWdl.eyJwcm9vZiI6eyJwaV9hIjpbIjE4MTE5Mjg3MTg1OTMzNjAxOTkzMTM5NTg1MzI3NjU5Mjc0ODQ1OTMzNjg5MzQ2NTU1MTkyODY0MDM0Mjg5MzAwMjA4MDk3MTIyODkwIiwiNjIyOTUwNjkyNzcwMzg5MjI1NjA1ODU1MjMxOTE4ODA0ODE0ODYwODEwMzg4ODU2MjE5ODM3Mjk2MzIxMzY1OTM4NTQxOTU3MDA3NiIsIjEiXSwicGlfYiI6W1siMjcyNTMzNjczNTQwODEwNTgxMjg2ODc1MjgyMzQ4NDE3NzA3OTkxMzM4MjAwNzMyNTg2NjU2MjE1NjE1OTU3MjI0MjgwMTE0MjgyOSIsIjQzNjA1NTYyNjkxMjIzNTM0ODY2MjQ1NjkyMjY0MDQ5ODMxNDI1NTYyMzk5ODA3OTAxNjkwMjkwMzI3MTUxMzE3ODUzMjA2ODc0MjYiXSxbIjE4NjEzMDEyMjk1MTc1NDY3NjQyMzMxMDkzNDkyODY4MjQ4NzYxNzQzMzk1Mjg3NzI0MzMxMTQ3OTA0NzE4NTY2MDEzMTI2NDMyNTMxIiwiMTkzNzA0NzU2MDcyMzIxNjAwOTQ2NjY3ODYxODEzODgxNzU5NTQyMjQ1ODYyMDAxNjUzMzUyNDU3NDkxNjM5NjEzMjk5NzM1NzkzMjIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MzQyNDIxMTE5MzA4MDQzMTM1OTk2NDE5NjYyMzAxMTEwMzU2MTQ5OTc1NDg1NDI0MDUyMjI1MDY0NTU4NTQ1MDg4NTc2NjY4NDU3IiwiMjE1MzU5NzU0NTU0MjU3MzUzNjI5MDY3NjA5NzU2MjkxMTEyMDk4NDgyNzQzNDI2NjU3MTQ4OTYyMjQ2OTE4NzAxNjA3MDM2NTQxOTUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIxOTIyOTA4NDg3MzcwNDU1MDM1NzIzMjg4NzE0Mjc3NDYwNTQ0MjI5NzMzNzIyOTE3NjU3OTIyOTAxMTM0MjA5MTU5NDE3NDk3NyIsIjYxMTA1MTc3NjgyNDk1NTkyMzgxOTM0Nzc0MzU0NTQ3OTIwMjQ3MzIxNzM4NjU0ODg5MDAyNzA4NDk2MjQzMjg2NTA3NjU2OTE0OTQiLCIxMjQzOTA0NzExNDI5OTYxODU4Nzc0MjIwNjQ3NjEwNzI0MjczNzk4OTE4NDU3OTkxNDg2MDMxNTY3MjQ0MTAwNzY3MjU5MjM5NzQ3Il19';

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
    rules: {
      query: {
        allowedIssuers: '*',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
        type: 'KYCCountryOfResidenceCredential',
        req: {
          countryCode: {
            $nin: [840, 120, 340, 509],
          },
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
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiSldaIn0.eyJpZCI6IjIzMjVhNTMzLTZhYjMtNGVkZi05YmZhLTI3OGEyOWQzMWI2YiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmODNjYzFlZC1kODU1LTRmNTEtYjBiMy00Y2Q5ODFiNmI0ZTgiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEwLCJjaXJjdWl0SWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFBWMiIsInByb29mIjp7InBpX2EiOlsiNTUzMTA3MzI4ODI5NTUyNzM5MzU2MTQzNDA5NTg1NDUyMTQwMTgyODkwNzUxOTA0NDc5OTEzMTY5OTMyMDg0MDY0NjcyNzE5MzQyIiwiNjQxNDE2NDM1MzQ0NDE0OTM3MzI1MTg2MDc1NTkzNzI0NzE5NTQ0MDE0ODI0Nzk3Nzk5Njg3MzQ2NDgwMTE3NTg2NDQ4ODYwMDE4NyIsIjEiXSwicGlfYiI6W1siMTg0ODc5MzkzNTIzNDE1NzU1MjI1NzgyOTA4ODE0NDc3NzcwMTY1NDM0NTE4MTc0MTIwMTYzNTQxNDE0MDY0NDgyNzU0MTgwMjA2MyIsIjI2OTA2NjkwNzMwNzAzODgwMjUwNzI2Njg2NTQ0MDgxNzUyNDg3ODI2MTAyMzI5NTczMDM3NzQxMTg0NjIxNzA4MDI3MTI0NTMyNzgiXSxbIjUwNTUwOTUyMjI3ODMxNjY5MjM0MjIyMDQ1MTQ2NDcyMjc1Mzc0NDAwNjk0NTg0MjA4NjkzNzY1ODc0OTI4NDg2NTMzNjMxNzMwNjAiLCI0ODMyMDIwNjAxNTk5NTY3ODkyMjIwNzQxNzE1NTk5MjI1NDIwMzgwMDQyNjc2MjM4NDAzNjY4Mzk5NjM0Mjg0MDY3ODI2MTQyODIiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2Mjk0OTY5MTk1Mzg1NDExNzM5MzM0NzIzOTgxNTExMjgxNDY3MDg3NDg1Mjk4MzQyMDMwODgxMTc5MzYxNTAyNzE0NDA2Njg0MTQiLCIxNDUxMzI1NzY3OTg5Nzg2MzAzNjk4OTU1MDY1NTc5NDI5MTQ1OTgzNDY3MDIwNjMxMDg3MjIzNjMyNjc5MDk3MTgwNzY1ODgyMzExNCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjEiLCIyNjMzNzQwNTIwMzYxMDU2NjAyOTI0MTk5NTg2NjE1NjE1MTQ2OTQzMzMxNTIxMjA2NzA1MDU3NDY5NjE0NDMzOTE4MDc4NjE3NyIsIjEwIiwiMjYzMzc0MDUyMDM2MTA1NjYwMjkyNDE5OTU4NjYxNTYxNTE0Njk0MzMzMTUyMTIwNjcwNTA1NzQ2OTYxNDQzMzkxODA3ODYxNzciLCIyMTQ5ODkwNTE1MzY4NjEzOTcyMDAyMzIyMTc0MzU3MDQ1NjI5MDQ0NTIzMDU4MDY3NzkzMTMwNzk3NDY0NDI4MjQ2OTY4MzIyNjAxMCIsIjIxNDk4OTA1MTUzNjg2MTM5NzIwMDIzMjIxNzQzNTcwNDU2MjkwNDQ1MjMwNTgwNjc3OTMxMzA3OTc0NjQ0MjgyNDY5NjgzMjI2MDEwIiwiMTY3MDg2MDcwNyIsIjMzNjYxNTQyMzkwMDkxOTQ2NDE5MzA3NTU5Mjg1MDQ4MzcwNDYwMCIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiJkaWQ6aWRlbjM6cG9seWdvbjptdW1iYWk6eDN2Z0JtU1dNZWNia3hGQXZUOHdhV2VqbUNMbXpIY3JHNTZzWGJBaEIiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TVRvUiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjExODQwMzkxMjMwNzg1NDA3MDY2ODkyMDc3MDc1NTQ2NTA2MzIzMDUyNzk2MTUxMDExNzMyMDQ1ODE3MTQxMDg3NDE5OTQ2MzE1ODUyIiwiMjE4MzM2MTY0NTYzNTg5NzU5OTM0NzAyODMxMzY4MDc1MzYzNjY1MzA5NzA4OTU5ODQ1NDU5MDYyNzgxNzQ3NjMyOTU5MzU1ODE2MjIiLCIxIl0sInBpX2IiOltbIjIxMTUzOTg0MDc3NzIxNDUzNjA4NDE4NTg2MDYyMzc5MzQ3MDEzNTU3MTMzNjMzNjQxOTg4NTIzODI4MjYyNTgwMTgyNTQzNzc0OTgzIiwiMjcwNDIxNDUxNjI4MzcxNTcyMjUzMzI0NDc2MjQzOTk4MjIxNzczMTY4MDAxNjExNzAyMjk0Nzk1MzM3NzU4MzI1MDQ0MjEwMDI2MSJdLFsiMjA1MTEzNDkzNDA3MTEwNTc1NjE5MTExNjk3NjM1MTE5NTA2MzA4NzMzMjc3ODExMTk3OTgwNDQyMTU4NzQ5OTQ2NzA1NzMxNDc3NzEiLCIxOTgxNzc1MTEwNTQzNjAzODU3MDcyOTg0MjAwNjgwOTM0OTExNTQ0MzMxNDc5NjUwNzU5NjkzODc2NjY5NTM3NjE4ODI0NTMwNjMwNSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMjc2NzE2NTA5OTY0MjgxOTk4OTI2NzI4MTYyOTc0MTYwMjcxNDI1NzA4ODMwNTU3MDYyOTExMjY1MTA3Nzc4MjE3Mzg4NDExMDkxOSIsIjY2NTc2ODM5MjMzNzg1MTkwODQxMDYxMTkyMjQ0NTgzNTk3NjUyMzUyOTA1MjY1OTcxMTIzMTk3OTg5NDU2Nzg0NDA0NTMxNzA4MzkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiJ9LCJwdWJfc2lnbmFscyI6WyIyNjMzNzQwNTIwMzYxMDU2NjAyOTI0MTk5NTg2NjE1NjE1MTQ2OTQzMzMxNTIxMjA2NzA1MDU3NDY5NjE0NDMzOTE4MDc4NjE3NyIsIjM1MzUwMTI4MzMxOTE5MTcyNDM2MDQyODAyODU1ODkxNzcyNTkwNjI0MTQ0NjMzMjA2NDk0MTM1NDE5ODE5MzQyMDI3MDc1NDIyMjEiLCIxMzU3ODkzODY3NDI5OTEzODA3MjQ3MTQ2MzY5NDA1NTIyNDgzMDg5MjcyNjIzNDA0ODUzMjUyMDMxNjM4NzcwNDg3ODAwMDAwODc5NSJdfQ';

  await expect(verifier.fullVerify(token, request)).resolves.not.toThrow();
});

test('TestResponseWithEmptyQueryRequest', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const userId =
    'did:iden3:polygon:mumbai:x3vgBmSWMecbkxFAvT8waWejmCLmzHcrG56sXbAhB';
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
    rules: {
      query: {
        allowedIssuers: '*',
        type: 'KYCCountryOfResidenceCredential',
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld',
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
        '553107328829552739356143409585452140182890751904479913169932084064672719342',
        '6414164353444149373251860755937247195440148247977996873464801175864488600187',
        '1',
      ],
      pi_b: [
        [
          '1848793935234157552257829088144777701654345181741201635414140644827541802063',
          '2690669073070388025072668654408175248782610232957303774118462170802712453278',
        ],
        [
          '5055095222783166923422204514647227537440069458420869376587492848653363173060',
          '483202060159956789222074171559922542038004267623840366839963428406782614282',
        ],
        ['1', '0'],
      ],
      pi_c: [
        '1629496919538541173933472398151128146708748529834203088117936150271440668414',
        '14513257679897863036989550655794291459834670206310872236326790971807658823114',
        '1',
      ],
      protocol: 'groth16',
      curve: 'bn128',
    },
    pub_signals: [
      '1',
      '26337405203610566029241995866156151469433315212067050574696144339180786177',
      '10',
      '26337405203610566029241995866156151469433315212067050574696144339180786177',
      '21498905153686139720023221743570456290445230580677931307974644282469683226010',
      '21498905153686139720023221743570456290445230580677931307974644282469683226010',
      '1670860707',
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
