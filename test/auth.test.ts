import {
  AUTHORIZATION_REQUEST_MESSAGE_TYPE,
  AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
  MEDIA_TYPE_SIGNED,
} from '@lib/protocol/constants';
import { v4 as uuidv4 } from 'uuid';

import { getCurveFromName } from 'ffjavascript';
import { FSKeyLoader } from '@lib/loaders/key';
import { ISchemaLoader, UniversalSchemaLoader } from '@lib/loaders/schema';
import { IStateResolver, ResolvedState, Resolvers } from '@lib/state/resolver';
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
import { Circuits, VerifyOpts } from '@lib/circuits/registry';
import { DIDResolutionResult } from 'did-resolver';
import { bytesToBase64url, hexToBytes } from '@0xpolygonid/js-sdk';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

const verificationKeyLoader: FSKeyLoader = new FSKeyLoader('./test/data');
const schemaLoader: ISchemaLoader = new UniversalSchemaLoader('ipfs.io');
const exampleDidDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/secp256k1recovery-2020/v2',
    {
      esrs2020:
        'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#',
      privateKeyJwk: {
        '@id': 'esrs2020:privateKeyJwk',
        '@type': '@json',
      },
      publicKeyHex: 'esrs2020:publicKeyHex',
      privateKeyHex: 'esrs2020:privateKeyHex',
      ethereumAddress: 'esrs2020:ethereumAddress',
    },
  ],
  id: 'did:example:123',
  verificationMethod: [
    {
      id: 'did:example:123#vm-1',
      controller: 'did:example:123',
      type: 'EcdsaSecp256k1VerificationKey2019',
      publicKeyJwk: {
        crv: 'secp256k1',
        kid: 'JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw',
        kty: 'EC',
        x: bytesToBase64url(
          hexToBytes(
            'fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479',
          ),
        ),
        y: bytesToBase64url(
          hexToBytes(
            '46393f8145252eea68afe67e287b3ed9b31685ba6c3b00060a73b9b1242d68f7',
          ),
        ),
      },
    },
  ],
  authentication: ['did:example:123#vm-1'],
};

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
const resolvers: Resolvers = {
  'polygon:mumbai': mockStateResolver,
};

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
      credentialSubject: {
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

  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);

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
      credentialSubject: {
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

  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);

  await expect(
    verifier.verifyAuthResponse(response, request),
  ).resolves.not.toThrow();
});

test('TestVerifyJWZ', async () => {
  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImYzZjVmM2JkLTJkOGItNDk0OS1hMDY5LTk3NTliZTdjZjUwYSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IjBJMHlZYVVqMXg5MXVZb3pCYnJDOG5BMWpkdkM3bmIwS3ByT21TQklqWXRaZnEvZVhVUHZtdDR2amw5cEdkN0xoSXg2bFVZT01NaHNJTTU4VmtWWGNUWHYyd2JaTDA5MkxWd1NXdk92N2Z2VXVoaTJtNG5VVHpvamFUdXZtdXVHbU1aYWZqSVpXMjBaeTRFdHUraXRpVUV3NnFjOU9QbTFmaXFZNitpeGFwYUpjdVYxQ1NHM0VvOFdYdkc1bGtzSllHOGJrQm1mSXNHaVF3aXdZR3BBVmVQbmsydTZGdkdpV2lKTDVscWZ3RjdPZ0kzem1qNUpCaU0vdUpLNGV5QlZTU3Bya2lZa3RKTnZKQWJtM3NYa1hudTh5UzdJZ2t5anpkK25LS1VTT1lhUzRQNmhTN2VNQ05aZ2RsTVBDamQ1UGFnanhNbDViSHBQQjRFbHpCUG5HVDd5ZDhpV0VHRGpWQ25oRDRBUGRUZVFVcjlXRWVtQmpuaWJtK1M4QzhrMnhBdzhBWm80T21zSkh4N0tnNVZJdGFyd3JMeTRDR1M1V1dlYTZTNDg4YzJyNG5vVmxubUFPck5EN0xtUTZMLzBseldNMUF4R2NRMVNzeUNjVHRldVpnNTZnd2lNUSs2Y016QVgvZjJJTjNGbG10cGxSUktxYzJjUkw4bnNWeUlFcTB5MzdRYWFBbG5vdEZJM3ZITnRjdFZUUjVucVozenpuWERhbjVqbXdLZWJFUFZ2ZEx4V3AxMERTTG5TWGlRb0VUMlNySEMxWXZsZmZEQXZqK2IrMVUxNTJxaElOZ1UrT213MlZFMlQxb1AwVUNtYkNrR0JsQys3Q0J3dFVncmhGN2h0eEw5b0FLRUNQV0ZIU1JRc2Y4Z0lrbUFMeU85VkNqMXhlYXBwUTlJPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjEzODIzMDQ0NDcyNzQ1Nzg2OTA4OTk1Mzc4OTc3NDI4NDY4MzM0NjkxMzM5OTAzNjI2MjUzMDUyNDY3NjQ1NTk1ODk2NzUxODg0MzI0IiwiMTQzNTY0NTcwMzIyNjU3ODg1NTcyNzU5NDcxMzAwNTIzNzIzMDc5MzUzNTcyNDUxNzIwODg2OTQ1NDA2MTcwNDgyMDAxNjQ3MzU1NTAiLCIxIl0sInBpX2IiOltbIjE0MDM4ODM3NDY4NzkwMTUwNTU1NzI0MzIxMjE0MzIxOTg3MzAzNjQ1NDA3NTkyMTI3MzYyNDY1MTg1ODA3NzMwNzM0Njg3MDA4NzQ4IiwiMTYxMjcxNzU1MDAzNDY2OTM0MjUyMDEyMzc0OTEyMjE2MDQ2MjYzMTczMzc1MzM2OTkwNTM4NzY5MzE5Njc1MzU3MjM3NDQ2MjM2MjgiXSxbIjc4MzU3MjYyNjY2ODQyOTk1NTY3NTY0ODY2OTU3NDM2Mjc4NDU1MjQzODIyODY2MzY3NTc5OTI3ODY3Mjg1MDA2NDAzMDQwMjQwNzgiLCIxMjYyNTEwOTg2MDAxMzE3NDY2MDY5NzU1MDUyODg3Mzc2MDU5MjI1NTkyOTA0OTk0NzAyNjcwNDcwMjc5MDExNzk1MDQ2NTAzMDg5MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTQ4MzE4MTIwNzg0MjIyNjgzMDI3MjEyODQ3NjA0OTQ2NTI1ODc4NDY5Mzc5NjY5MDU3MjE3NjMzMjM4NDM2MzY0MDc0MjUwNzM4OTEiLCIxMTQwMzg0OTI3NTUyMzM5MjU5NDE2MTA0MDQ0MDU0NDc5OTk4MTM1ODQ1ODYzMTg2ODI5MDc5MTgwNzE4NjYyNzUxMDMyMTQzODgyMyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCIxNDE3Mjc3MDA4ODYwMjI1NTgyNTczMzYxMTM2NTM5ODcxODkzNTM3MTI0NDU3NTI1MzA1NjM2MTMwNzgyMzMwMzAyODQ0MjkwNzk1MCIsIjEiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjEiLCIyMjk4MjU4OTcwODk5Njg1MTY3NTExMTk0MDQ5OTIzNjk1OTE5MTM3NzIwODk0NTI1NDY4MzM1ODU3MDU3NjU1MjIxMDk4OTI0OTczIiwiMTY4MTM4NDQ4MyIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjAiLCIxIiwiMTk5NjA0MjQiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXSwidnAiOnsiQHR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vaWRlbjMvY2xhaW0tc2NoZW1hLXZvY2FiL21haW4vc2NoZW1hcy9qc29uLWxkL2t5Yy12NC5qc29ubGQiXSwiQHR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkB0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNH19fX1dfX0.eyJwcm9vZiI6eyJwaV9hIjpbIjE4ODQ2ODQ0NzY0ODk0Mzc0OTc2ODE4Njc4MDgxNzAwNjMzOTY5NTAzMzQ3MzkxMTQ2ODAzMTQwNjU2NDAxNzQzNzQwMzkxNjMyMzUzIiwiMTI3Mjc1ODM1OTYyNTI1NjgwNjM2NjEwNzk4NTU0MTg2MTAxNDExNDgzOTg4NTc4NjUwNDUzNDk4MjQxODI0Mzg5MDUyNjE3NjQwOTAiLCIxIl0sInBpX2IiOltbIjE5OTQ4MDc5NzU5OTI4Mzk3Nzk3MzUwNDQwNzgwMjEwMjQ3MzA3MTI1MjY4MjE1NDY2MDU0MDI4MzgyNTQ0Mzk2MDM3MjM4OTY1NTMzIiwiMTY2NjE0MDI1ODI1MTQ3NDM2OTc4NTk4NTE0MzcwODAyNjU1MjQ0MjgxNTM5OTE5NTk2MzU2OTI1MTAyMDM2MjkzNzA3MzE2MDY4NDgiXSxbIjE3MzgyMjA4OTc2NzM5NjY1NDYyNTI2OTEwMTQ5MTY2NzE5NzM5MTMwNzgyNzc5NTk2NjI2OTQ4NjI2NDc2ODI2ODU3OTQ2OTE1MjAyIiwiMTc1MzQ1OTM2Mjg1NDQ1NDQ5MzgxOTE0Njc4ODA1MjIyNTg5NjAzNzM4NTExNTk0MDI2NDg5NDE5ODI3Mzk1NjA3MTU1ODg1MTE5NzMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjIxNTY4OTUwMTU3NDc2MjAwOTU0MDAxNTg3Mjg0NTg4NDQwMDk3ODg5NDQ5MjgyNjgyMzg1MDUyNTczODA3NTExOTU3NTgwNTUzNzcwIiwiMTg4MjcyMzI3NjEyMDEzNTIxNDQ4OTM0ODk3NTcwODEwMjIxMTMzMjExNjMyODg3NDg5NjgxOTc0NTg5NDM4MTYzNjg3MDUwNTM0MTUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCI4MTcwNzQwNjM1NzM4Mjg0NTk1NzI0NjA2MTQxMzgzMzExNzQ4MzcwNzE1MzAyNjQ3NDQ4NDQ3NDk2MjA1MDcyMTg5NjUzNTQ2MTk3IiwiNTIyOTY2ODY4NjU1NzYzNzAxNzc4MTE1NzM1NjMwNDc2OTY2MTcwOTIzODY3MDI3MDYxMzU2MDg4NzY5OTM1Mjk0NDk5NjU1MDI5NSJdfQ';

  await expect(verifier.verifyJWZ(token)).resolves.not.toThrow();
});

test('TestFullVerify', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const reason = 'age verification';
  const request: AuthorizationRequestMessage =
    createAuthorizationRequestWithMessage(reason, '', sender, callback);
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  const proofRequest: ZKPRequest = {
    id: 1,
    circuitId: 'credentialAtomicQuerySigV2',
    query: {
      allowedIssuers: ['*'],
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
      type: 'KYCCountryOfResidenceCredential',
      credentialSubject: {
        countryCode: {
          $nin: [840, 120, 340, 509],
        },
      },
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);
  await verifier.setupAuthV2ZKPPacker();
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImRjNjY1NWY3LTIxY2MtNGM2OC1iYmI5LTNhOTgzMTAwNDJiNCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6ImFUSStsMnljbk5Sa0xUandEcnRabUhkQ2h2c0VTUFZRb1dXSEpIeitiSHpqV0xqNEdRNlF6N3hSaHFZWjBzU1RSL3J0b3FEeEFKT2ZkSko0ZmRyYzc3Qzg1K3hqM2Z5d1B5T3kxblUrNC9TQVJLK3NLdStYNzhyRUtuWUJVeWFjVmlRbUhYQnpqeHhiR2VzMGpSSkt0bDNuWkc1ZDdsVkI4aW50clA0c09yRExzcC9hUDVlVVAwUTF4dHRieEVvaWJvL1dKZnZQeUowU01GRFVoSEdPaG0zL1cyNnNIY25jY1lJNDNXRkYyckJ0bEtaKytvUEE1M0lJYnNWazRFSlJ5NFpSaHhMY0RmTDc2ZFB0N0RkRk1LSmxaUW1EeE91VHJFK1AzNFB6eWdsN3BOUzJPMUFpck5FVDl6Y3F4WWlmdGhDbFkwOFVTaWpvejVid1BQZDgxYzB0R0doaExRb0FUNlR2WEdOeGlpTXdpQi8xTzkyYy9nRHcxQVlMb1RFK1NTeHRIUDhkRHU1LzNaZEw3RjVWeFIwUUhHVGZCMHRtcm5Bc0RYcXhKZi9PRG0xcmtablJlRit4aWVySVl6WkRZRld1VGNRZzZrcGlXTjA3N0xxTlJMMDJUMWZWMXBCNGdaWTd4YTVqdC96UjVacDZmQ1B3eE54SlZZWjNjZ1lIbVdPZVkya3dFQU1HSjQ2VEdpMnhOSC9mOE9qK1gvV2VJb0xWeDBXeitwRjZYV2RXdksramNMVENzSElIUSs1VHdmeGtNZ1RhbVl5cnlpaGo0VzVIN05uMEJCR09UemVvZlRFc3ZWUlpjbHlJVmMySlUzTlBUTE1TMGVLQnBiUWt1N3RyKzh4bDVybERsUktnbUJNb1B4SXArMlpjZk5INEZJOEhGQlhpa0JVPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjczMzE4MjU1MTYzNTg5OTE1MDE2NjY5MjgyNDgwNDEzNDUyOTg2ODE5NjE0ODIxMDE1NTgzNTE4MDUxODQ2NTM2OTAxMDY2NDkyNjAiLCIyMDI1NzM0Nzk5Nzc2OTU1OTc4Mjk0ODg3MTI5MjA3NjExODg2Nzc2NTkzMzkwNzMyOTMwNTk0MjE1OTk2MjA1OTg0MTc3NzI1ODkwNiIsIjEiXSwicGlfYiI6W1siMTk5NDAyMzc5NTM0MzU2ODExMDMxNjAxNDg3MjM1NzI3MTkwMTA5NTk4MDc4NzgxNTUxMTk0NDIxNjc2NDk1MzIyMDM4NzE3MDc5MTYiLCI4Nzc5MTc3NTg1MDExNTQ5OTA2MjU2NTk0NDg2MDE0Njk1OTg0ODUwNTI3NjQwNjA0NjM1NjAxNTUwNzQ4OTQ2NzM3MzEwMzI3ODczIl0sWyIxODYzNTI0ODEyMzcyNjQyNzMwNjg1MjE3ODIwMzcyMjAwODY1MTA3NDA0ODI4NDMyMjg2NzUxNTc1MjgwNTQyOTgxNDQzMzcyMzY0NiIsIjQ1NDM3MDE3Njk2NjUxNTAzOTkwMzY4MTI0NDE4Njg1OTQ5MzA0NjM4MDgyNDc5NTE3OTU2OTUwNTMyNDkwODkzODIxMDQwMDg3MzciXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjM1MDY2OTQ4OTgwMzYxNTI0NjQzMTQ5ODIyODY0NDA3OTY4OTg0MDU1MzYxNjkwMDk4MjM2ODIwMTg1MTY1OTc2ODk1OTE5NDkzNzkiLCIxOTgxNzQ3MzYwMTEzNDg3NDc2NTAxNjU5NjM5NzUxNzAyNDc1ODEwMjI4ODY5MzMyNTQzMjQxNjAyNjg1NDIxNDk2ODg4NTE3NDgzMyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCIxNDE3Mjc3MDA4ODYwMjI1NTgyNTczMzYxMTM2NTM5ODcxODkzNTM3MTI0NDU3NTI1MzA1NjM2MTMwNzgyMzMwMzAyODQ0MjkwNzk1MCIsIjEiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjEiLCI3NzczNTIxMTcyNjYzMzQ3Njc2NTY4MDQxOTUyMDI1NzY5NTQ4OTA3ODI0MDY0MTYxNTY1MzQ0Njk4MjM1MjkwMTM4NzY3MjU2NTQ0IiwiMTY4MTM4NTc2NyIsIjIwMTEzNDcxMzc1NDI3OTIzNTExNzM3MzIzNjg0MTUwNjM0NDI4NSIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNjg4NDM5MjgzMzUwMzc5NjY0NzA2NTA1NjI0NDI1OTExOTg2NjEzODk0NjQ3MjAxMjM1Mzk4Nzk1NjI3NjQ3OTg2OTMyOTk4OTEyIiwiNTM4NDE3OTE4MDQwNjA5OTMyNzIzNTgwMTU2NDAwNDE4MDMxMjMyNjc4NTMzNzcxNzA5MDQzMjk4NTQ3NDkyMjA1NTg5OTgxNTMyMSIsIjEiXSwicGlfYiI6W1siNDA3MDQ4MjI5OTAxNDYzOTc5NTQxMjk2ODkzMzYyNzY3ODc1MTIxMTYwNDAwOTU0NzQ3ODc5MjgwODU1Njc0MDQ3ODU2MjA4MTA5MiIsIjMwOTkxNDcwNDIzMTY4NTI5OTk0NzY4NjQxMzQ2NzcxNjEzOTI4MzYxMjkwNTkzNzE0MDQwMTMwNjk3NDM3Njg4MTI4NTg5ODAxNzIiXSxbIjgzNzA0NjU5ODU5MDEzMjc1NTk4MTEwNDY0MDc2OTI0OTE2MDE4ODExNTY4MjcwNzE0MTYzNzk2NTIwMzM1MzUyMTk4NTYwOTA0MDAiLCI3NjEwNDYxNjMxOTMyMTUyODU0OTUyODg3MTA0MTk4OTM5NzE3ODUxMzA5MDk4OTUwMzI0Nzg4NDYyNTQ1MzMzNTk3NzAzMTgxNjQyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI4NTA5MDM5NTU3MDkwNjEzMDk5ODcyNjExMzgyMjUzNzc4Mzc0MzU0NDc3NjQ5OTI3NjcyNzEzMzcwNzMzMjgwOTg4MDg4MTEyNjcwIiwiODMwMDk2MTAyMjc2NjMyMjI1MjA5NzA5NzgwNjI3NTEyMzMzODA2MDM3ODIyMTA0NjE1NzEwMjE2NDIwNDY1ODg3NTIwNjQ4NzY2NyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTUxMzE0MDUzMDIzMzkyMTUxNTgwOTIzNTM4ODc4MDEzNDY4MTI0NTYxMjg1ODc0NDkwMDI5Nzc0MDQ5MDQ0NzczODU3MzMxNCIsIjkyNjQ5ODIyODY2MTcwMjg2NDQzNDQ5ODg0MjQ3MTA1NTgyODM1NTk5Mjk0ODA3NTQ4OTMyNTI2NDE3NjY4NDczMTk5NzU4MTQzNyIsIjcwMzg3MDcxOTU3NTE5NDE0NjUyMjE2MTYxMDk4MjI4MDM1NjM1NjY4NzczMjA5ODk2MDc1NzIzOTc0Mjk1MTI0NjM0Mjk3NzcwMjkiXX0';

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});

test('TestFullVerify JWS', async () => {
  const token = `eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZToxMjMjdm0tMSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiJ9.eyJ0eXBlIjoiaHR0cHM6Ly9pZGVuMy1jb21tdW5pY2F0aW9uLmlvL2F1dGhvcml6YXRpb24vMS4wL3Jlc3BvbnNlIiwiZnJvbSI6ImRpZDpleGFtcGxlOjEyMyIsImJvZHkiOnsic2NvcGUiOlt7InR5cGUiOiJ6ZXJva25vd2xlZGdlIiwiY2lyY3VpdF9pZCI6ImF1dGgiLCJwdWJfc2lnbmFscyI6WyIxIiwiMTgzMTE1NjA1MjUzODMzMTk3MTkzMTEzOTQ5NTcwNjQ4MjAwOTEzNTQ5NzYzMTA1OTk4MTg3OTcxNTcxODk1Njg2MjE0NjY5NTA4MTEiLCIzMjM0MTY5MjUyNjQ2NjYyMTc2MTcyODg1Njk3NDI1NjQ3MDM2MzI4NTA4MTYwMzU3NjEwODQwMDI3MjAwOTAzNzczNTMyOTc5MjAiXSwicHJvb2ZfZGF0YSI6eyJwaV9hIjpbIjExMTMwODQzMTUwNTQwNzg5Mjk5NDU4OTkwNTg2MDIwMDAwNzE5MjgwMjQ2MTUzNzk3ODgyODQzMjE0MjkwNTQxOTgwNTIyMzc1MDcyIiwiMTMwMDg0MTkxMjk0Mzc4MTcyMzAyMjAzMjM1NTgzNjg5MzgzMTEzMjkyMDc4Mzc4ODQ1NTUzMTgzODI1NDQ2NTc4NDYwNTc2MjcxMyIsIjEiXSwicGlfYiI6W1siMjA2MTU3Njg1MzY5ODg0MzgzMzY1Mzc3Nzc5MDkwNDIzNTIwNTYzOTI4NjIyNTE3ODU3MjI3OTY2Mzc1OTAyMTIxNjA1NjEzNTE2NTYiLCIxMDM3MTE0NDgwNjEwNzc3ODg5MDUzODg1NzcwMDg1NTEwODY2NzYyMjA0MjIxNTA5Njk3MTc0NzIwMzEwNTk5NzQ1NDYyNTgxNDA4MCJdLFsiMTk1OTg1NDEzNTA4MDQ0Nzg1NDkxNDEyMDc4MzUwMjg2NzExMTEwNjM5MTU2MzU1ODA2Nzk2OTQ5MDc2MzU5MTQyNzk5Mjg2Nzc4MTIiLCIxNTI2NDU1MzA0NTUxNzA2NTY2OTE3MTU4NDk0Mzk2NDMyMjExNzM5NzY0NTE0NzAwNjkwOTE2NzQyNzgwOTgzNzkyOTQ1ODAxMjkxMyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTY0NDMzMDkyNzk4MjU1MDg4OTMwODYyNTEyOTAwMDM5MzY5MzUwNzczNDg3NTQwOTc0NzA4MTg1MjM1NTgwODI1MDIzNjQ4MjIwNDkiLCIyOTg0MTgwMjI3NzY2MDQ4MTAwNTEwMTIwNDA3MTUwNzUyMDUyMzM0NTcxODc2NjgxMzA0OTk5NTk1NTQ0MTM4MTU1NjExOTYzMjczIiwiMSJdLCJwcm90b2NvbCI6IiJ9fV19fQ.de_qaDM7VYFaPUCNDGsvwF04tT4S4nXBO8dqXnU8XAof0Uip5LDCe4-IjEBPxu0sLh8BxcvPHMYMjx_pvPcqWw`;
  const sender = 'did:example:123';
  const callback = 'https://test.com/callback';
  const reason = 'reason';
  const request: AuthorizationRequestMessage = createAuthorizationRequest(
    reason,
    sender,
    callback,
  );
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);
  request.id = '4f3549b-0c9d-47f8-968c-c9b0c10b8847';
  request.thid = '1f3549b-0c9d-47f8-968c-c9b0c10b8847';
  request.typ = MEDIA_TYPE_SIGNED;
  request.type = AUTHORIZATION_REQUEST_MESSAGE_TYPE;
  request.to =
    'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7';
  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);
  const resolveDIDDocument = {
    resolve: () =>
      Promise.resolve({ didDocument: exampleDidDoc } as DIDResolutionResult),
  };

  await verifier.setupJWSPacker(null, resolveDIDDocument);

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});

test('TestResponseWithEmptyQueryRequest_ErrorCase', async () => {
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
  request['message'] = 'test';
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

  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);

  try {
    await verifier.verifyAuthResponse(response, request);
  } catch (e) {
    expect(e.toString()).toContain(
      'operator that was used is not equal to request',
    );
  }
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

test('verify jwz with selective disclosure', async () => {
  const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
  const callback = 'https://test.com/callback';
  const reason = 'age verification';
  const request: AuthorizationRequestMessage =
    createAuthorizationRequestWithMessage(reason, '', sender, callback);
  expect(request.body.scope.length).toEqual(0);
  expect(request.body.callbackUrl).toEqual(callback);
  expect(request.body.reason).toEqual(reason);
  expect(request.from).toEqual(sender);

  const proofRequest: ZKPRequest = {
    id: 1,
    circuitId: 'credentialAtomicQuerySigV2',
    query: {
      allowedIssuers: ['*'],
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
      type: 'KYCAgeCredential',
      credentialSubject: {
        birthday: {},
      },
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const verifier = new Verifier(verificationKeyLoader, schemaLoader, resolvers);
  await verifier.setupAuthV2ZKPPacker();
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImYzZjVmM2JkLTJkOGItNDk0OS1hMDY5LTk3NTliZTdjZjUwYSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IjBJMHlZYVVqMXg5MXVZb3pCYnJDOG5BMWpkdkM3bmIwS3ByT21TQklqWXRaZnEvZVhVUHZtdDR2amw5cEdkN0xoSXg2bFVZT01NaHNJTTU4VmtWWGNUWHYyd2JaTDA5MkxWd1NXdk92N2Z2VXVoaTJtNG5VVHpvamFUdXZtdXVHbU1aYWZqSVpXMjBaeTRFdHUraXRpVUV3NnFjOU9QbTFmaXFZNitpeGFwYUpjdVYxQ1NHM0VvOFdYdkc1bGtzSllHOGJrQm1mSXNHaVF3aXdZR3BBVmVQbmsydTZGdkdpV2lKTDVscWZ3RjdPZ0kzem1qNUpCaU0vdUpLNGV5QlZTU3Bya2lZa3RKTnZKQWJtM3NYa1hudTh5UzdJZ2t5anpkK25LS1VTT1lhUzRQNmhTN2VNQ05aZ2RsTVBDamQ1UGFnanhNbDViSHBQQjRFbHpCUG5HVDd5ZDhpV0VHRGpWQ25oRDRBUGRUZVFVcjlXRWVtQmpuaWJtK1M4QzhrMnhBdzhBWm80T21zSkh4N0tnNVZJdGFyd3JMeTRDR1M1V1dlYTZTNDg4YzJyNG5vVmxubUFPck5EN0xtUTZMLzBseldNMUF4R2NRMVNzeUNjVHRldVpnNTZnd2lNUSs2Y016QVgvZjJJTjNGbG10cGxSUktxYzJjUkw4bnNWeUlFcTB5MzdRYWFBbG5vdEZJM3ZITnRjdFZUUjVucVozenpuWERhbjVqbXdLZWJFUFZ2ZEx4V3AxMERTTG5TWGlRb0VUMlNySEMxWXZsZmZEQXZqK2IrMVUxNTJxaElOZ1UrT213MlZFMlQxb1AwVUNtYkNrR0JsQys3Q0J3dFVncmhGN2h0eEw5b0FLRUNQV0ZIU1JRc2Y4Z0lrbUFMeU85VkNqMXhlYXBwUTlJPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjEzODIzMDQ0NDcyNzQ1Nzg2OTA4OTk1Mzc4OTc3NDI4NDY4MzM0NjkxMzM5OTAzNjI2MjUzMDUyNDY3NjQ1NTk1ODk2NzUxODg0MzI0IiwiMTQzNTY0NTcwMzIyNjU3ODg1NTcyNzU5NDcxMzAwNTIzNzIzMDc5MzUzNTcyNDUxNzIwODg2OTQ1NDA2MTcwNDgyMDAxNjQ3MzU1NTAiLCIxIl0sInBpX2IiOltbIjE0MDM4ODM3NDY4NzkwMTUwNTU1NzI0MzIxMjE0MzIxOTg3MzAzNjQ1NDA3NTkyMTI3MzYyNDY1MTg1ODA3NzMwNzM0Njg3MDA4NzQ4IiwiMTYxMjcxNzU1MDAzNDY2OTM0MjUyMDEyMzc0OTEyMjE2MDQ2MjYzMTczMzc1MzM2OTkwNTM4NzY5MzE5Njc1MzU3MjM3NDQ2MjM2MjgiXSxbIjc4MzU3MjYyNjY2ODQyOTk1NTY3NTY0ODY2OTU3NDM2Mjc4NDU1MjQzODIyODY2MzY3NTc5OTI3ODY3Mjg1MDA2NDAzMDQwMjQwNzgiLCIxMjYyNTEwOTg2MDAxMzE3NDY2MDY5NzU1MDUyODg3Mzc2MDU5MjI1NTkyOTA0OTk0NzAyNjcwNDcwMjc5MDExNzk1MDQ2NTAzMDg5MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTQ4MzE4MTIwNzg0MjIyNjgzMDI3MjEyODQ3NjA0OTQ2NTI1ODc4NDY5Mzc5NjY5MDU3MjE3NjMzMjM4NDM2MzY0MDc0MjUwNzM4OTEiLCIxMTQwMzg0OTI3NTUyMzM5MjU5NDE2MTA0MDQ0MDU0NDc5OTk4MTM1ODQ1ODYzMTg2ODI5MDc5MTgwNzE4NjYyNzUxMDMyMTQzODgyMyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCIxNDE3Mjc3MDA4ODYwMjI1NTgyNTczMzYxMTM2NTM5ODcxODkzNTM3MTI0NDU3NTI1MzA1NjM2MTMwNzgyMzMwMzAyODQ0MjkwNzk1MCIsIjEiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjEiLCIyMjk4MjU4OTcwODk5Njg1MTY3NTExMTk0MDQ5OTIzNjk1OTE5MTM3NzIwODk0NTI1NDY4MzM1ODU3MDU3NjU1MjIxMDk4OTI0OTczIiwiMTY4MTM4NDQ4MyIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjAiLCIxIiwiMTk5NjA0MjQiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXSwidnAiOnsiQHR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vaWRlbjMvY2xhaW0tc2NoZW1hLXZvY2FiL21haW4vc2NoZW1hcy9qc29uLWxkL2t5Yy12NC5qc29ubGQiXSwiQHR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkB0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNH19fX1dfX0.eyJwcm9vZiI6eyJwaV9hIjpbIjE4ODQ2ODQ0NzY0ODk0Mzc0OTc2ODE4Njc4MDgxNzAwNjMzOTY5NTAzMzQ3MzkxMTQ2ODAzMTQwNjU2NDAxNzQzNzQwMzkxNjMyMzUzIiwiMTI3Mjc1ODM1OTYyNTI1NjgwNjM2NjEwNzk4NTU0MTg2MTAxNDExNDgzOTg4NTc4NjUwNDUzNDk4MjQxODI0Mzg5MDUyNjE3NjQwOTAiLCIxIl0sInBpX2IiOltbIjE5OTQ4MDc5NzU5OTI4Mzk3Nzk3MzUwNDQwNzgwMjEwMjQ3MzA3MTI1MjY4MjE1NDY2MDU0MDI4MzgyNTQ0Mzk2MDM3MjM4OTY1NTMzIiwiMTY2NjE0MDI1ODI1MTQ3NDM2OTc4NTk4NTE0MzcwODAyNjU1MjQ0MjgxNTM5OTE5NTk2MzU2OTI1MTAyMDM2MjkzNzA3MzE2MDY4NDgiXSxbIjE3MzgyMjA4OTc2NzM5NjY1NDYyNTI2OTEwMTQ5MTY2NzE5NzM5MTMwNzgyNzc5NTk2NjI2OTQ4NjI2NDc2ODI2ODU3OTQ2OTE1MjAyIiwiMTc1MzQ1OTM2Mjg1NDQ1NDQ5MzgxOTE0Njc4ODA1MjIyNTg5NjAzNzM4NTExNTk0MDI2NDg5NDE5ODI3Mzk1NjA3MTU1ODg1MTE5NzMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjIxNTY4OTUwMTU3NDc2MjAwOTU0MDAxNTg3Mjg0NTg4NDQwMDk3ODg5NDQ5MjgyNjgyMzg1MDUyNTczODA3NTExOTU3NTgwNTUzNzcwIiwiMTg4MjcyMzI3NjEyMDEzNTIxNDQ4OTM0ODk3NTcwODEwMjIxMTMzMjExNjMyODg3NDg5NjgxOTc0NTg5NDM4MTYzNjg3MDUwNTM0MTUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCI4MTcwNzQwNjM1NzM4Mjg0NTk1NzI0NjA2MTQxMzgzMzExNzQ4MzcwNzE1MzAyNjQ3NDQ4NDQ3NDk2MjA1MDcyMTg5NjUzNTQ2MTk3IiwiNTIyOTY2ODY4NjU1NzYzNzAxNzc4MTE1NzM1NjMwNDc2OTY2MTcwOTIzODY3MDI3MDYxMzU2MDg4NzY5OTM1Mjk0NDk5NjU1MDI5NSJdfQ';

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});
