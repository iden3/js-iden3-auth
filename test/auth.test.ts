import { Circuits } from '../src/circuits/registry';
import {
  AuthorizationRequestMessage,
  AuthorizationResponseMessage,
  ZKPRequest,
  ZKPResponse,
} from '../src/protocol/models';
import {
  createAuthorizationRequest,
  createAuthorizationRequestWithMessage,
  Verifier,
} from '../src/auth/auth';

import { AUTHORIZATION_RESPONSE_MESSAGE_TYPE } from '../src/protocol/constants';
import { v4 as uuidv4 } from 'uuid';

import { getCurveFromName } from 'ffjavascript';
import { FSKeyLoader } from '../src/loaders/key';
import { ISchemaLoader, UniversalSchemaLoader } from '../src/loaders/schema';
import { IStateResolver, ResolvedState } from '../src/state/resolver';
import { AuthPubSignals } from '../src/circuits/auth';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

var verificationKeyLoader: FSKeyLoader = new FSKeyLoader('./test/data');
var schemaLoader: ISchemaLoader = new UniversalSchemaLoader('ipfs.io');

class MockResolver implements IStateResolver {
  async resolve(id: bigint, state: bigint): Promise<ResolvedState> {
    let t: ResolvedState = {
      latest: true,
      state: null,
      transitionTimestamp: 0,
    };
    return t;
  }
}
var mockStateResolver: MockResolver = new MockResolver();

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
    id: 24,
    circuit_id: 'credentialAtomicQueryMTP',
    rules: {
      challenge: 84239,
      query: {
        allowedIssuers: '1195GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLN9',
        schema: {
          type: 'KYCAgeCredential',
          url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
        },
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

  let verifier = new Verifier(
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
  const userId = '119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ';
  const reason = 'test';
  const message = 'message to sign';
  const request: AuthorizationRequestMessage = createAuthorizationRequestWithMessage(
    reason,
    message,
    sender,
    callback,
  );
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; 

  const proofRequest: ZKPRequest = {
    id: 1,
    circuit_id: 'credentialAtomicQueryMTP',
    rules: {
      query: {
        allowedIssuers: ['*'],
        schema: {
          type: 'KYCCountryOfResidenceCredential',
          url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
        },
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
    circuit_id: 'credentialAtomicQueryMTP',
    proof: {
      "pi_a": [
        "957698408427964949373649712039920043210974666537246242527666231574736447215",
        "4086301798091555580700861865212439093760939259461303470105592576075967110809",
        "1"
       ],
       "pi_b": [
        [
         "17761559932897315893618895130972320113328240504534127684296053239008480650132",
         "5632193781365169642645888319571038406614807943044397798965094551600628234503"
        ],
        [
         "1365440307473149802051965484085369690014133594254254856398071522896525497247",
         "9143247083381732337710902360194843027755305930598838459668134140717530368519"
        ],
        [
         "1",
         "0"
        ]
       ],
       "pi_c": [
        "16707768020019049851803695616000699953210287095055797633254316035548791886996",
        "20859199949100338932805050654787060104015161388984781255169527105633884420687",
        "1"
       ],
       "protocol": "groth16",
       "curve": "bn128"
    },
    pub_signals: [
      "379949150130214723420589610911161895495647789006649785264738141299135414272",
      "18656147546666944484453899241916469544090258810192803949522794490493271005313",
      "1",
      "17339270624307006522829587570402128825147845744601780689258033623056405933706",
      "26599707002460144379092755370384635496563807452878989192352627271768342528",
      "1642074362",
      "106590880073303418818490710639556704462",
      "2",
      "5",
      "840",
      "120",
      "340",
      "509",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0"
     ]
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

  let verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('TestVerifyJWZ', async () => {
  let verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  let token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjA5YjM4NDE1LTY3ZjAtNGE2Ny1hZTRhLTA3M2U4MGQzODg3MiIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tcGxhaW4tanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJmcm9tIjoiMTE5dHFjZVdkUmQyRjZXbkF5VnVGUVJGakszV1VYcTJMb3JTUHlHOUxKIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01MTloiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjk1NzY5ODQwODQyNzk2NDk0OTM3MzY0OTcxMjAzOTkyMDA0MzIxMDk3NDY2NjUzNzI0NjI0MjUyNzY2NjIzMTU3NDczNjQ0NzIxNSIsIjQwODYzMDE3OTgwOTE1NTU1ODA3MDA4NjE4NjUyMTI0MzkwOTM3NjA5MzkyNTk0NjEzMDM0NzAxMDU1OTI1NzYwNzU5NjcxMTA4MDkiLCIxIl0sInBpX2IiOltbIjE3NzYxNTU5OTMyODk3MzE1ODkzNjE4ODk1MTMwOTcyMzIwMTEzMzI4MjQwNTA0NTM0MTI3Njg0Mjk2MDUzMjM5MDA4NDgwNjUwMTMyIiwiNTYzMjE5Mzc4MTM2NTE2OTY0MjY0NTg4ODMxOTU3MTAzODQwNjYxNDgwNzk0MzA0NDM5Nzc5ODk2NTA5NDU1MTYwMDYyODIzNDUwMyJdLFsiMTM2NTQ0MDMwNzQ3MzE0OTgwMjA1MTk2NTQ4NDA4NTM2OTY5MDAxNDEzMzU5NDI1NDI1NDg1NjM5ODA3MTUyMjg5NjUyNTQ5NzI0NyIsIjkxNDMyNDcwODMzODE3MzIzMzc3MTA5MDIzNjAxOTQ4NDMwMjc3NTUzMDU5MzA1OTg4Mzg0NTk2NjgxMzQxNDA3MTc1MzAzNjg1MTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NzA3NzY4MDIwMDE5MDQ5ODUxODAzNjk1NjE2MDAwNjk5OTUzMjEwMjg3MDk1MDU1Nzk3NjMzMjU0MzE2MDM1NTQ4NzkxODg2OTk2IiwiMjA4NTkxOTk5NDkxMDAzMzg5MzI4MDUwNTA2NTQ3ODcwNjAxMDQwMTUxNjEzODg5ODQ3ODEyNTUxNjk1MjcxMDU2MzM4ODQ0MjA2ODciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE2NDIwNzQzNjIiLCIxMDY1OTA4ODAwNzMzMDM0MTg4MTg0OTA3MTA2Mzk1NTY3MDQ0NjIiLCIyIiwiNSIsIjg0MCIsIjEyMCIsIjM0MCIsIjUwOSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjMwMTc3ODIzODI1MzEwODkxMzY0NzgzNjU4MjAzMDMwNDY1NDkyMDYwMjA5MzEyNjc0NjgwNzk4NzY2ODM5NDE5MjcxMDgyNDkxNDEiLCI0OTAyMzUzODc4OTI0MTk2NzUyMTI2NDY2MTczMTM3NjQ0MjE4MDY2MTY0MDE5ODc4NDM4MzU3MDc0NDkwNjU4MTY2MjUyNTMxMzIxIiwiMSJdLCJwaV9iIjpbWyIxMjExNDEwOTAwNzkxMDg1NjM1MTk4ODgxNzQ0MjY1NTE3NjY3NTQ0OTE5NDcyOTc4MzYyNjQxNjUyMjY5NjAwMTA1NjIyMjA1MDA3NCIsIjE3NzIyMDA5NDMxNjI0MzUwMDAzMTU4MjgwOTcxNzk1NDQ2NTgwMzkxNTIzOTY3NzYxMzI4MzIzNjU4NDgxMTc2NDM3MTYxNzkxOTU2Il0sWyIxNzYyMzU3NzEzMzgzNzU4MDEzNzY4MDQ3NDQwNzk2NjY5OTA5Nzc0MDQxMzk1ODkxNzU2Njc0ODE4OTQ3OTM0NDQ2OTY5MTY1MDUyOCIsIjIxNDg2ODU3NDI2OTU4NTgxNzE4MjYwNDU4NzgyMjUxMjUwNzcwNTg0NzU0NzkyMDc4MTIwNDA0NzM3NDkzNzI3Njg1NTg3MjExNjM0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjY4OTYyNDQ2ODc3MTI5MTc0MDY1MzY2MjczMjYxNzQzODEyODAwMzc2NzQyNDUwMDI0NjIyODI3NjA3MTYzMDI5NjQ4MjUxNTM0NiIsIjE1NDI3MzQxMDYxNzcxNDYyNjI1OTg3NjkzNzI4NjY0Njk0MTA0Mzk0OTcxNjE5NzUyOTk2NjUyNTQ2OTkzNzEwNjM5MDQ3NzMzNjE4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiODQ5NTg4MzgyMTE1NzY5NjE2MjY1NDAzNDE4MDIwNjk2OTU1NjYxNTQ5NzgxOTM2Mzc4OTc4NTUyMTI4MzQ5OTk3MDQ4MTk4MDk0MCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19';

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
    id: 1,
    circuit_id: 'credentialAtomicQueryMTP',
    rules: {
      query: {
        allowedIssuers: ['*'],
        schema: {
          type: 'KYCCountryOfResidenceCredential',
          url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
        },
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

  let verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  let token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6IkpXWiJ9.eyJpZCI6IjA5YjM4NDE1LTY3ZjAtNGE2Ny1hZTRhLTA3M2U4MGQzODg3MiIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJ0eXAiOiJhcHBsaWNhdGlvbi9pZGVuM2NvbW0tcGxhaW4tanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJmcm9tIjoiMTE5dHFjZVdkUmQyRjZXbkF5VnVGUVJGakszV1VYcTJMb3JTUHlHOUxKIiwidG8iOiIxMTI1R0pxZ3c2WUVzS0Z3ajYzR1k4N01NeFBMOWt3REt4UFVpd01MTloiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjk1NzY5ODQwODQyNzk2NDk0OTM3MzY0OTcxMjAzOTkyMDA0MzIxMDk3NDY2NjUzNzI0NjI0MjUyNzY2NjIzMTU3NDczNjQ0NzIxNSIsIjQwODYzMDE3OTgwOTE1NTU1ODA3MDA4NjE4NjUyMTI0MzkwOTM3NjA5MzkyNTk0NjEzMDM0NzAxMDU1OTI1NzYwNzU5NjcxMTA4MDkiLCIxIl0sInBpX2IiOltbIjE3NzYxNTU5OTMyODk3MzE1ODkzNjE4ODk1MTMwOTcyMzIwMTEzMzI4MjQwNTA0NTM0MTI3Njg0Mjk2MDUzMjM5MDA4NDgwNjUwMTMyIiwiNTYzMjE5Mzc4MTM2NTE2OTY0MjY0NTg4ODMxOTU3MTAzODQwNjYxNDgwNzk0MzA0NDM5Nzc5ODk2NTA5NDU1MTYwMDYyODIzNDUwMyJdLFsiMTM2NTQ0MDMwNzQ3MzE0OTgwMjA1MTk2NTQ4NDA4NTM2OTY5MDAxNDEzMzU5NDI1NDI1NDg1NjM5ODA3MTUyMjg5NjUyNTQ5NzI0NyIsIjkxNDMyNDcwODMzODE3MzIzMzc3MTA5MDIzNjAxOTQ4NDMwMjc3NTUzMDU5MzA1OTg4Mzg0NTk2NjgxMzQxNDA3MTc1MzAzNjg1MTkiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE2NzA3NzY4MDIwMDE5MDQ5ODUxODAzNjk1NjE2MDAwNjk5OTUzMjEwMjg3MDk1MDU1Nzk3NjMzMjU0MzE2MDM1NTQ4NzkxODg2OTk2IiwiMjA4NTkxOTk5NDkxMDAzMzg5MzI4MDUwNTA2NTQ3ODcwNjAxMDQwMTUxNjEzODg5ODQ3ODEyNTUxNjk1MjcxMDU2MzM4ODQ0MjA2ODciLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIiwiMTg2NTYxNDc1NDY2NjY5NDQ0ODQ0NTM4OTkyNDE5MTY0Njk1NDQwOTAyNTg4MTAxOTI4MDM5NDk1MjI3OTQ0OTA0OTMyNzEwMDUzMTMiLCIxIiwiMTczMzkyNzA2MjQzMDcwMDY1MjI4Mjk1ODc1NzA0MDIxMjg4MjUxNDc4NDU3NDQ2MDE3ODA2ODkyNTgwMzM2MjMwNTY0MDU5MzM3MDYiLCIyNjU5OTcwNzAwMjQ2MDE0NDM3OTA5Mjc1NTM3MDM4NDYzNTQ5NjU2MzgwNzQ1Mjg3ODk4OTE5MjM1MjYyNzI3MTc2ODM0MjUyOCIsIjE2NDIwNzQzNjIiLCIxMDY1OTA4ODAwNzMzMDM0MTg4MTg0OTA3MTA2Mzk1NTY3MDQ0NjIiLCIyIiwiNSIsIjg0MCIsIjEyMCIsIjM0MCIsIjUwOSIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCJdfV19fQ.eyJwcm9vZiI6eyJwaV9hIjpbIjMwMTc3ODIzODI1MzEwODkxMzY0NzgzNjU4MjAzMDMwNDY1NDkyMDYwMjA5MzEyNjc0NjgwNzk4NzY2ODM5NDE5MjcxMDgyNDkxNDEiLCI0OTAyMzUzODc4OTI0MTk2NzUyMTI2NDY2MTczMTM3NjQ0MjE4MDY2MTY0MDE5ODc4NDM4MzU3MDc0NDkwNjU4MTY2MjUyNTMxMzIxIiwiMSJdLCJwaV9iIjpbWyIxMjExNDEwOTAwNzkxMDg1NjM1MTk4ODgxNzQ0MjY1NTE3NjY3NTQ0OTE5NDcyOTc4MzYyNjQxNjUyMjY5NjAwMTA1NjIyMjA1MDA3NCIsIjE3NzIyMDA5NDMxNjI0MzUwMDAzMTU4MjgwOTcxNzk1NDQ2NTgwMzkxNTIzOTY3NzYxMzI4MzIzNjU4NDgxMTc2NDM3MTYxNzkxOTU2Il0sWyIxNzYyMzU3NzEzMzgzNzU4MDEzNzY4MDQ3NDQwNzk2NjY5OTA5Nzc0MDQxMzk1ODkxNzU2Njc0ODE4OTQ3OTM0NDQ2OTY5MTY1MDUyOCIsIjIxNDg2ODU3NDI2OTU4NTgxNzE4MjYwNDU4NzgyMjUxMjUwNzcwNTg0NzU0NzkyMDc4MTIwNDA0NzM3NDkzNzI3Njg1NTg3MjExNjM0Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIxNjY4OTYyNDQ2ODc3MTI5MTc0MDY1MzY2MjczMjYxNzQzODEyODAwMzc2NzQyNDUwMDI0NjIyODI3NjA3MTYzMDI5NjQ4MjUxNTM0NiIsIjE1NDI3MzQxMDYxNzcxNDYyNjI1OTg3NjkzNzI4NjY0Njk0MTA0Mzk0OTcxNjE5NzUyOTk2NjUyNTQ2OTkzNzEwNjM5MDQ3NzMzNjE4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiODQ5NTg4MzgyMTE1NzY5NjE2MjY1NDAzNDE4MDIwNjk2OTU1NjYxNTQ5NzgxOTM2Mzc4OTc4NTUyMTI4MzQ5OTk3MDQ4MTk4MDk0MCIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19';

  await expect(verifier.fullVerify(token, request)).resolves.not.toThrow();
});

test('TestResponseWithEmptyQueryRequest', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const userId = '119tqceWdRd2F6WnAyVuFQRFjK3WUXq2LorSPyG9LJ';
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
    id: 24,
    circuit_id: 'credentialAtomicQueryMTP',
    rules: {
      query: {
        allowedIssuers: ['*'],
        schema: {
          type: 'KYCCountryOfResidenceCredential',
          url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
        },
      },
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const mtpProof: ZKPResponse = {
    id: proofRequest.id,
    circuit_id: 'credentialAtomicQueryMTP',
    proof: {
      "pi_a": [
       "1886918534832719851890321463403403984129131165546634145956170501591930441217",
       "6655579421620637446732087343801770832201862323895906495279402105137977303781",
       "1"
      ],
      "pi_b": [
       [
        "9169079072239264579542136478120546648602417723883575380902565713898445847407",
        "19892529896743597497143526216812621221702441646677187616198045140410139604850"
       ],
       [
        "2227131843642265252863230630671907130727822896030596855045908403574129004371",
        "11206781133823943671644452813496911200888630423721769626699105815720196027761"
       ],
       [
        "1",
        "0"
       ]
      ],
      "pi_c": [
       "4939638222702977380323761508903944673657041168500738909686531050713946789170",
       "9393906835076280711459107422291218224824322615260507505878201886261132992290",
       "1"
      ],
      "protocol": "groth16",
      "curve": "bn128"
     },
    pub_signals: [
      "379949150130214723420589610911161895495647789006649785264738141299135414272",
      "18656147546666944484453899241916469544090258810192803949522794490493271005313",
      "1",
      "17339270624307006522829587570402128825147845744601780689258033623056405933706",
      "26599707002460144379092755370384635496563807452878989192352627271768342528",
      "1642074362",
      "106590880073303418818490710639556704462",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0",
      "0"
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

  let verifier = new Verifier(
    verificationKeyLoader,
    schemaLoader,
    mockStateResolver,
  );

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('registry: get existing circuit', () => {
  const type = Circuits.getCircuitPubSignals('auth');
  const instance = new type([
    '1',
    '5816868615164565912277677884704888703982258184820398645933682814085602171910',
    '286312392162647260160287083374160163061246635086990474403590223113720496128',
  ]);
  expect(type).not.toBeNull();
  expect(instance).not.toBeNull();
  expect(instance.verifyQuery).not.toBeNull();
  expect((instance as AuthPubSignals).challenge.toString()).toEqual('1');
  expect((instance as AuthPubSignals).userId.string()).toEqual(
    '113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj',
  );
  expect((instance as AuthPubSignals).userState.toString()).toEqual(
    '5816868615164565912277677884704888703982258184820398645933682814085602171910',
  );
});
