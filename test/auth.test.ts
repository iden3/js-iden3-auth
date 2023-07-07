import {
  AUTHORIZATION_REQUEST_MESSAGE_TYPE,
  AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
  MEDIA_TYPE_SIGNED,
} from '@lib/protocol/constants';
import { v4 as uuidv4 } from 'uuid';

import { getCurveFromName } from 'ffjavascript';
import { FSKeyLoader } from '@lib/loaders/loaders';
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
import {
  DocumentLoader,
  getDocumentLoader,
} from '@iden3/js-jsonld-merklization';

afterAll(async () => {
  const curve = await getCurveFromName('bn128');
  curve.terminate();
});

const verificationKeyLoader: FSKeyLoader = new FSKeyLoader('./test/data');
let connectionString = process.env.IPFS_URL;
if (!connectionString) {
  connectionString = 'https://ipfs.io';
}
const schemaLoader: DocumentLoader = getDocumentLoader({
  ipfsNodeURL: connectionString,
});
const exampleDidDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    {
      EcdsaSecp256k1RecoveryMethod2020:
        'https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020',
      blockchainAccountId: 'https://w3id.org/security#blockchainAccountId',
    },
  ],
  id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
  verificationMethod: [
    {
      id: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020',
      type: 'EcdsaSecp256k1RecoveryMethod2020',
      controller: 'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
      blockchainAccountId:
        'eip155:137:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65',
    },
  ],
  authentication: [
    'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020',
  ],
  assertionMethod: [
    'did:pkh:poly:0x7141E4d20F7644DC8c0AdCA8a520EC83C6cABD65#Recovery2020',
  ],
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

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
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

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );
  const opts: VerifyOpts = {
    acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
  };
  await expect(
    verifier.verifyAuthResponse(response, request, opts),
  ).resolves.not.toThrow();
});

test('TestVerifyJWZ', async () => {
  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );

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

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImRjNjY1NWY3LTIxY2MtNGM2OC1iYmI5LTNhOTgzMTAwNDJiNCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6ImFUSStsMnljbk5Sa0xUandEcnRabUhkQ2h2c0VTUFZRb1dXSEpIeitiSHpqV0xqNEdRNlF6N3hSaHFZWjBzU1RSL3J0b3FEeEFKT2ZkSko0ZmRyYzc3Qzg1K3hqM2Z5d1B5T3kxblUrNC9TQVJLK3NLdStYNzhyRUtuWUJVeWFjVmlRbUhYQnpqeHhiR2VzMGpSSkt0bDNuWkc1ZDdsVkI4aW50clA0c09yRExzcC9hUDVlVVAwUTF4dHRieEVvaWJvL1dKZnZQeUowU01GRFVoSEdPaG0zL1cyNnNIY25jY1lJNDNXRkYyckJ0bEtaKytvUEE1M0lJYnNWazRFSlJ5NFpSaHhMY0RmTDc2ZFB0N0RkRk1LSmxaUW1EeE91VHJFK1AzNFB6eWdsN3BOUzJPMUFpck5FVDl6Y3F4WWlmdGhDbFkwOFVTaWpvejVid1BQZDgxYzB0R0doaExRb0FUNlR2WEdOeGlpTXdpQi8xTzkyYy9nRHcxQVlMb1RFK1NTeHRIUDhkRHU1LzNaZEw3RjVWeFIwUUhHVGZCMHRtcm5Bc0RYcXhKZi9PRG0xcmtablJlRit4aWVySVl6WkRZRld1VGNRZzZrcGlXTjA3N0xxTlJMMDJUMWZWMXBCNGdaWTd4YTVqdC96UjVacDZmQ1B3eE54SlZZWjNjZ1lIbVdPZVkya3dFQU1HSjQ2VEdpMnhOSC9mOE9qK1gvV2VJb0xWeDBXeitwRjZYV2RXdksramNMVENzSElIUSs1VHdmeGtNZ1RhbVl5cnlpaGo0VzVIN05uMEJCR09UemVvZlRFc3ZWUlpjbHlJVmMySlUzTlBUTE1TMGVLQnBiUWt1N3RyKzh4bDVybERsUktnbUJNb1B4SXArMlpjZk5INEZJOEhGQlhpa0JVPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjczMzE4MjU1MTYzNTg5OTE1MDE2NjY5MjgyNDgwNDEzNDUyOTg2ODE5NjE0ODIxMDE1NTgzNTE4MDUxODQ2NTM2OTAxMDY2NDkyNjAiLCIyMDI1NzM0Nzk5Nzc2OTU1OTc4Mjk0ODg3MTI5MjA3NjExODg2Nzc2NTkzMzkwNzMyOTMwNTk0MjE1OTk2MjA1OTg0MTc3NzI1ODkwNiIsIjEiXSwicGlfYiI6W1siMTk5NDAyMzc5NTM0MzU2ODExMDMxNjAxNDg3MjM1NzI3MTkwMTA5NTk4MDc4NzgxNTUxMTk0NDIxNjc2NDk1MzIyMDM4NzE3MDc5MTYiLCI4Nzc5MTc3NTg1MDExNTQ5OTA2MjU2NTk0NDg2MDE0Njk1OTg0ODUwNTI3NjQwNjA0NjM1NjAxNTUwNzQ4OTQ2NzM3MzEwMzI3ODczIl0sWyIxODYzNTI0ODEyMzcyNjQyNzMwNjg1MjE3ODIwMzcyMjAwODY1MTA3NDA0ODI4NDMyMjg2NzUxNTc1MjgwNTQyOTgxNDQzMzcyMzY0NiIsIjQ1NDM3MDE3Njk2NjUxNTAzOTkwMzY4MTI0NDE4Njg1OTQ5MzA0NjM4MDgyNDc5NTE3OTU2OTUwNTMyNDkwODkzODIxMDQwMDg3MzciXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjM1MDY2OTQ4OTgwMzYxNTI0NjQzMTQ5ODIyODY0NDA3OTY4OTg0MDU1MzYxNjkwMDk4MjM2ODIwMTg1MTY1OTc2ODk1OTE5NDkzNzkiLCIxOTgxNzQ3MzYwMTEzNDg3NDc2NTAxNjU5NjM5NzUxNzAyNDc1ODEwMjI4ODY5MzMyNTQzMjQxNjAyNjg1NDIxNDk2ODg4NTE3NDgzMyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCIxNDE3Mjc3MDA4ODYwMjI1NTgyNTczMzYxMTM2NTM5ODcxODkzNTM3MTI0NDU3NTI1MzA1NjM2MTMwNzgyMzMwMzAyODQ0MjkwNzk1MCIsIjEiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjEiLCI3NzczNTIxMTcyNjYzMzQ3Njc2NTY4MDQxOTUyMDI1NzY5NTQ4OTA3ODI0MDY0MTYxNTY1MzQ0Njk4MjM1MjkwMTM4NzY3MjU2NTQ0IiwiMTY4MTM4NTc2NyIsIjIwMTEzNDcxMzc1NDI3OTIzNTExNzM3MzIzNjg0MTUwNjM0NDI4NSIsIjAiLCIxNzAwMjQzNzExOTQzNDYxODc4MzU0NTY5NDYzMzAzODUzNzM4MDcyNjMzOTk5NDI0NDY4NDM0ODkxMzg0NDkyMzQyMjQ3MDgwNjg0NCIsIjAiLCI1IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjIwNjg4NDM5MjgzMzUwMzc5NjY0NzA2NTA1NjI0NDI1OTExOTg2NjEzODk0NjQ3MjAxMjM1Mzk4Nzk1NjI3NjQ3OTg2OTMyOTk4OTEyIiwiNTM4NDE3OTE4MDQwNjA5OTMyNzIzNTgwMTU2NDAwNDE4MDMxMjMyNjc4NTMzNzcxNzA5MDQzMjk4NTQ3NDkyMjA1NTg5OTgxNTMyMSIsIjEiXSwicGlfYiI6W1siNDA3MDQ4MjI5OTAxNDYzOTc5NTQxMjk2ODkzMzYyNzY3ODc1MTIxMTYwNDAwOTU0NzQ3ODc5MjgwODU1Njc0MDQ3ODU2MjA4MTA5MiIsIjMwOTkxNDcwNDIzMTY4NTI5OTk0NzY4NjQxMzQ2NzcxNjEzOTI4MzYxMjkwNTkzNzE0MDQwMTMwNjk3NDM3Njg4MTI4NTg5ODAxNzIiXSxbIjgzNzA0NjU5ODU5MDEzMjc1NTk4MTEwNDY0MDc2OTI0OTE2MDE4ODExNTY4MjcwNzE0MTYzNzk2NTIwMzM1MzUyMTk4NTYwOTA0MDAiLCI3NjEwNDYxNjMxOTMyMTUyODU0OTUyODg3MTA0MTk4OTM5NzE3ODUxMzA5MDk4OTUwMzI0Nzg4NDYyNTQ1MzMzNTk3NzAzMTgxNjQyIl0sWyIxIiwiMCJdXSwicGlfYyI6WyI4NTA5MDM5NTU3MDkwNjEzMDk5ODcyNjExMzgyMjUzNzc4Mzc0MzU0NDc3NjQ5OTI3NjcyNzEzMzcwNzMzMjgwOTg4MDg4MTEyNjcwIiwiODMwMDk2MTAyMjc2NjMyMjI1MjA5NzA5NzgwNjI3NTEyMzMzODA2MDM3ODIyMTA0NjE1NzEwMjE2NDIwNDY1ODg3NTIwNjQ4NzY2NyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTUxMzE0MDUzMDIzMzkyMTUxNTgwOTIzNTM4ODc4MDEzNDY4MTI0NTYxMjg1ODc0NDkwMDI5Nzc0MDQ5MDQ0NzczODU3MzMxNCIsIjkyNjQ5ODIyODY2MTcwMjg2NDQzNDQ5ODg0MjQ3MTA1NTgyODM1NTk5Mjk0ODA3NTQ4OTMyNTI2NDE3NjY4NDczMTk5NzU4MTQzNyIsIjcwMzg3MDcxOTU3NTE5NDE0NjUyMjE2MTYxMDk4MjI4MDM1NjM1NjY4NzczMjA5ODk2MDc1NzIzOTc0Mjk1MTI0NjM0Mjk3NzcwMjkiXX0';

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
    acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});

test('TestFullVerify JWS', async () => {
  const token =
    'eyJhbGciOiJFUzI1NkstUiIsImtpZCI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUjUmVjb3ZlcnkyMDIwIiwidHlwIjoiYXBwbGljYXRpb24vaWRlbjNjb21tLXNpZ25lZC1qc29uIn0.eyJpZCI6IjJjOGQ5NzQ3LTQ0MTAtNGU5My1iZjg0LTRlYTNjZmY4MmY0MCIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1zaWduZWQtanNvbiIsInR5cGUiOiJodHRwczovL2lkZW4zLWNvbW11bmljYXRpb24uaW8vYXV0aG9yaXphdGlvbi8xLjAvcmVzcG9uc2UiLCJ0aGlkIjoiN2YzOGExOTMtMDkxOC00YTQ4LTlmYWMtMzZhZGZkYjhiNTQyIiwiYm9keSI6eyJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRJZCI6ImNyZWRlbnRpYWxBdG9taWNRdWVyeVNpZ1YyIiwicHJvb2YiOnsicGlfYSI6WyIxMzI3Njk4Nzc5MjQ5MjM0OTA2MDcxMDc3NTEyOTUxMjYxNzY1NjMzODcxMDkxMzE3NDA0NzE0NTcyMDY4Mjk4NzU0MzUwNjY3NDY0IiwiMjA1NDcyOTI1MzQ0MDgxNzA4NDQwODc3MzY2MDQ0OTYyNjQ3MzI2NjUxNDkxMDEzMzMxNzk3NTg5NTAwMjM0NTgwMjA1Njg5NzMzNTYiLCIxIl0sInBpX2IiOltbIjcyNTI1MDEyNjE5ODM1NTYwMjM1NjA3MzI1MjIzODk2MjIxMDY4MTA5OTUxNzkxNjI0MjY2NzcyNDM2MjQwNTQ0Mzc2Nzc1ODI4MCIsIjgyNDU2MTQzMTExNjUzNTUyNzcyNTgyNTg1NTA0MTI5MTUzNjAzNTc2MjEyMDY5OTA0Mjk3NTE3ODk2NTgwNTI1ODY0Mjc2NjgyMDMiXSxbIjg0MjA4OTI3MTI5OTMyMTU5OTU3NjkwMDQ3MzU2Njc5MzY3MDk4MzY5MTY4MzU4MDM2Njc2NjI1NzQxMTcyNjEzNjI2OTgxMzI1MjkiLCIxMDgyOTQzMjI5MDkyODY3MjM1NjAzNjExMTgxNjE4NTQ0MDU3NTgwMDI1NDQzODAyMzUzNTA3MzUzNTY1ODMzOTE0MzMzODAzNDAyNyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTIwNTc1NzM1NDQ2Mzc1NDA1MzE2MjIxNDc2NDg2NjE0MDc1NzM1MzY2MjU0MjM0MzY1ODE0MTk2OTY3NzYwOTMxOTY5Nzc5OTg2MzkiLCIxNTIwMzMwMjIxNjcyOTEzOTcwNjQyNjcyMzc5Mzk5Mjk0MjI5NjY1NTU0NDA4MTEwODkzMTE2MjIwMTQxOTcxNzI0MjU4NTQzOTg2NSIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjgwMTg1ODg4MjE0NzE5Mzk2MjQ3MTE0MjE5MjIwNzkzOTU0NTE1MDc3NTQzNzU5Nzg0MDgyMzA1MjQ3OTI3ODY4NjI5OTc1MDMiLCIxNDE5MzMwNDc0NzUwMTMzMTE4MTgwOTcxNTkxMjQ4NzIzNjUyNzAwMzkyNTA4MjEwNjc1MjM3Njc5NjA5OTg5MDIwMTkyODE4NTY5MCIsIjEiLCIyMjk0MjU5NDE1NjI2NjY2NTQyNjYxMzQ2Mjc3MTcyNTMyNzMxNDM4MjY0NzQyNjk1OTA0NDg2MzQ0Njg2NjYxMzAwMzc1MTkzOCIsIjEiLCIzMTY5NjEyMzY4MDg3OTA1MzQyNzg2NTE0MDk5NDQ5Mjk3NDA0MzgzODc0MzcxMzU2OTI0ODI4MDgyMTQzNjExOTUzNjIxODU5NzU5IiwiMTY4NzQzMzc0OCIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjIiLCIyIiwiMjAwMDAxMDEiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXX1dfSwiZnJvbSI6ImRpZDpwa2g6cG9seToweDcxNDFFNGQyMEY3NjQ0REM4YzBBZENBOGE1MjBFQzgzQzZjQUJENjUiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFMUHF2YXlOUXo5VEEycjVWUHhVdWdvRjE4dGVHVTU4M3pKODU5d2Z5In0.bWc2ECABj7nvHatD8AXWNJM2VtfhkIjNwz5BBIK9zBMsP0-UWLEWdAWcosiLkYoL0KWwZpgEOrPPepl6T5gC-AA';
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

  const proofRequest: ZKPRequest = {
    id: 1,
    circuitId: 'credentialAtomicQuerySigV2',
    query: {
      allowedIssuers: ['*'],
      context:
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld',
      type: 'KYCAgeCredential',
      credentialSubject: {
        birthday: {
          $lt: 20000101,
        },
      },
    },
  };
  request.body.scope.push(proofRequest);

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );
  const resolveDIDDocument = {
    resolve: () =>
      Promise.resolve({ didDocument: exampleDidDoc } as DIDResolutionResult),
  };

  verifier.setupJWSPacker(null, resolveDIDDocument);

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
    acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
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

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );

  try {
    await verifier.verifyAuthResponse(response, request);
  } catch (e) {
    expect(e.toString()).toContain(
      'Error: failed to validate operators: empty credentialSubject request available only for equal operation',
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

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6ImYzZjVmM2JkLTJkOGItNDk0OS1hMDY5LTk3NTliZTdjZjUwYSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHciLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxSnBScVpOUlR4a2lDVU40VlNmTFE3S0E0UHpIU3d3VnduU0tTRkt0dyIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUpwUnFaTlJUeGtpQ1VONFZTZkxRN0tBNFB6SFN3d1Z3blNLU0ZLdHcjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IjBJMHlZYVVqMXg5MXVZb3pCYnJDOG5BMWpkdkM3bmIwS3ByT21TQklqWXRaZnEvZVhVUHZtdDR2amw5cEdkN0xoSXg2bFVZT01NaHNJTTU4VmtWWGNUWHYyd2JaTDA5MkxWd1NXdk92N2Z2VXVoaTJtNG5VVHpvamFUdXZtdXVHbU1aYWZqSVpXMjBaeTRFdHUraXRpVUV3NnFjOU9QbTFmaXFZNitpeGFwYUpjdVYxQ1NHM0VvOFdYdkc1bGtzSllHOGJrQm1mSXNHaVF3aXdZR3BBVmVQbmsydTZGdkdpV2lKTDVscWZ3RjdPZ0kzem1qNUpCaU0vdUpLNGV5QlZTU3Bya2lZa3RKTnZKQWJtM3NYa1hudTh5UzdJZ2t5anpkK25LS1VTT1lhUzRQNmhTN2VNQ05aZ2RsTVBDamQ1UGFnanhNbDViSHBQQjRFbHpCUG5HVDd5ZDhpV0VHRGpWQ25oRDRBUGRUZVFVcjlXRWVtQmpuaWJtK1M4QzhrMnhBdzhBWm80T21zSkh4N0tnNVZJdGFyd3JMeTRDR1M1V1dlYTZTNDg4YzJyNG5vVmxubUFPck5EN0xtUTZMLzBseldNMUF4R2NRMVNzeUNjVHRldVpnNTZnd2lNUSs2Y016QVgvZjJJTjNGbG10cGxSUktxYzJjUkw4bnNWeUlFcTB5MzdRYWFBbG5vdEZJM3ZITnRjdFZUUjVucVozenpuWERhbjVqbXdLZWJFUFZ2ZEx4V3AxMERTTG5TWGlRb0VUMlNySEMxWXZsZmZEQXZqK2IrMVUxNTJxaElOZ1UrT213MlZFMlQxb1AwVUNtYkNrR0JsQys3Q0J3dFVncmhGN2h0eEw5b0FLRUNQV0ZIU1JRc2Y4Z0lrbUFMeU85VkNqMXhlYXBwUTlJPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjEzODIzMDQ0NDcyNzQ1Nzg2OTA4OTk1Mzc4OTc3NDI4NDY4MzM0NjkxMzM5OTAzNjI2MjUzMDUyNDY3NjQ1NTk1ODk2NzUxODg0MzI0IiwiMTQzNTY0NTcwMzIyNjU3ODg1NTcyNzU5NDcxMzAwNTIzNzIzMDc5MzUzNTcyNDUxNzIwODg2OTQ1NDA2MTcwNDgyMDAxNjQ3MzU1NTAiLCIxIl0sInBpX2IiOltbIjE0MDM4ODM3NDY4NzkwMTUwNTU1NzI0MzIxMjE0MzIxOTg3MzAzNjQ1NDA3NTkyMTI3MzYyNDY1MTg1ODA3NzMwNzM0Njg3MDA4NzQ4IiwiMTYxMjcxNzU1MDAzNDY2OTM0MjUyMDEyMzc0OTEyMjE2MDQ2MjYzMTczMzc1MzM2OTkwNTM4NzY5MzE5Njc1MzU3MjM3NDQ2MjM2MjgiXSxbIjc4MzU3MjYyNjY2ODQyOTk1NTY3NTY0ODY2OTU3NDM2Mjc4NDU1MjQzODIyODY2MzY3NTc5OTI3ODY3Mjg1MDA2NDAzMDQwMjQwNzgiLCIxMjYyNTEwOTg2MDAxMzE3NDY2MDY5NzU1MDUyODg3Mzc2MDU5MjI1NTkyOTA0OTk0NzAyNjcwNDcwMjc5MDExNzk1MDQ2NTAzMDg5MyJdLFsiMSIsIjAiXV0sInBpX2MiOlsiMTQ4MzE4MTIwNzg0MjIyNjgzMDI3MjEyODQ3NjA0OTQ2NTI1ODc4NDY5Mzc5NjY5MDU3MjE3NjMzMjM4NDM2MzY0MDc0MjUwNzM4OTEiLCIxMTQwMzg0OTI3NTUyMzM5MjU5NDE2MTA0MDQ0MDU0NDc5OTk4MTM1ODQ1ODYzMTg2ODI5MDc5MTgwNzE4NjYyNzUxMDMyMTQzODgyMyIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIxIiwiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCIxNDE3Mjc3MDA4ODYwMjI1NTgyNTczMzYxMTM2NTM5ODcxODkzNTM3MTI0NDU3NTI1MzA1NjM2MTMwNzgyMzMwMzAyODQ0MjkwNzk1MCIsIjEiLCIyNzc1Mjc2NjgyMzM3MTQ3MTQwODI0ODIyNTcwODY4MTMxMzc2NDg2NjIzMTY1NTE4NzM2NjA3MTg4MTA3MDkxODk4NDQ3MTA0MiIsIjEiLCIyMjk4MjU4OTcwODk5Njg1MTY3NTExMTk0MDQ5OTIzNjk1OTE5MTM3NzIwODk0NTI1NDY4MzM1ODU3MDU3NjU1MjIxMDk4OTI0OTczIiwiMTY4MTM4NDQ4MyIsIjI2NzgzMTUyMTkyMjU1ODAyNzIwNjA4MjM5MDA0MzMyMTc5Njk0NCIsIjAiLCIyMDM3NjAzMzgzMjM3MTEwOTE3NzY4MzA0ODQ1NjAxNDUyNTkwNTExOTE3MzY3NDk4NTg0MzkxNTQ0NTYzNDcyNjE2NzQ1MDk4OTYzMCIsIjAiLCIxIiwiMTk5NjA0MjQiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiXSwidnAiOnsiQHR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vaWRlbjMvY2xhaW0tc2NoZW1hLXZvY2FiL21haW4vc2NoZW1hcy9qc29uLWxkL2t5Yy12NC5qc29ubGQiXSwiQHR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJLWUNBZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7IkB0eXBlIjoiS1lDQWdlQ3JlZGVudGlhbCIsImJpcnRoZGF5IjoxOTk2MDQyNH19fX1dfX0.eyJwcm9vZiI6eyJwaV9hIjpbIjE4ODQ2ODQ0NzY0ODk0Mzc0OTc2ODE4Njc4MDgxNzAwNjMzOTY5NTAzMzQ3MzkxMTQ2ODAzMTQwNjU2NDAxNzQzNzQwMzkxNjMyMzUzIiwiMTI3Mjc1ODM1OTYyNTI1NjgwNjM2NjEwNzk4NTU0MTg2MTAxNDExNDgzOTg4NTc4NjUwNDUzNDk4MjQxODI0Mzg5MDUyNjE3NjQwOTAiLCIxIl0sInBpX2IiOltbIjE5OTQ4MDc5NzU5OTI4Mzk3Nzk3MzUwNDQwNzgwMjEwMjQ3MzA3MTI1MjY4MjE1NDY2MDU0MDI4MzgyNTQ0Mzk2MDM3MjM4OTY1NTMzIiwiMTY2NjE0MDI1ODI1MTQ3NDM2OTc4NTk4NTE0MzcwODAyNjU1MjQ0MjgxNTM5OTE5NTk2MzU2OTI1MTAyMDM2MjkzNzA3MzE2MDY4NDgiXSxbIjE3MzgyMjA4OTc2NzM5NjY1NDYyNTI2OTEwMTQ5MTY2NzE5NzM5MTMwNzgyNzc5NTk2NjI2OTQ4NjI2NDc2ODI2ODU3OTQ2OTE1MjAyIiwiMTc1MzQ1OTM2Mjg1NDQ1NDQ5MzgxOTE0Njc4ODA1MjIyNTg5NjAzNzM4NTExNTk0MDI2NDg5NDE5ODI3Mzk1NjA3MTU1ODg1MTE5NzMiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjIxNTY4OTUwMTU3NDc2MjAwOTU0MDAxNTg3Mjg0NTg4NDQwMDk3ODg5NDQ5MjgyNjgyMzg1MDUyNTczODA3NTExOTU3NTgwNTUzNzcwIiwiMTg4MjcyMzI3NjEyMDEzNTIxNDQ4OTM0ODk3NTcwODEwMjIxMTMzMjExNjMyODg3NDg5NjgxOTc0NTg5NDM4MTYzNjg3MDUwNTM0MTUiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMjE1MTMxNDA1MzAyMzM5MjE1MTU4MDkyMzUzODg3ODAxMzQ2ODEyNDU2MTI4NTg3NDQ5MDAyOTc3NDA0OTA0NDc3Mzg1NzMzMTQiLCI4MTcwNzQwNjM1NzM4Mjg0NTk1NzI0NjA2MTQxMzgzMzExNzQ4MzcwNzE1MzAyNjQ3NDQ4NDQ3NDk2MjA1MDcyMTg5NjUzNTQ2MTk3IiwiNTIyOTY2ODY4NjU1NzYzNzAxNzc4MTE1NzM1NjMwNDc2OTY2MTcwOTIzODY3MDI3MDYxMzU2MDg4NzY5OTM1Mjk0NDk5NjU1MDI5NSJdfQ';

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
    acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});

test('test verify empty credential subject', async () => {
  const sender =
    'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7';
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
        'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
      type: 'KYCEmployee',
    },
  };
  request.body.scope.push(proofRequest);

  expect(request.body.scope.length).toEqual(1);

  const verifier = await Verifier.newVerifier(
    verificationKeyLoader,
    resolvers,
    {
      documentLoader: schemaLoader,
    },
  );
  request.id = '28494007-9c49-4f1a-9694-7700c08865bf';
  request.thid = 'ee92ab12-2671-457e-aa5e-8158c205a985'; // because it's used in the response

  const token =
    'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6Ijc0MWU2MTA4LTM4MzgtNDFiYS1hMGIwLTlhZmZkZjY1NTg2YSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiIxNjEwN2QwYi01ZDU3LTQ1OWEtYWJiMi00OWE2Mjg2YTA5NTMiLCJmcm9tIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUd5VDhtTUdydlRqTVdDelRHOE1YVG9neGp6UFRVYjJMa2tMM0FKMTEiLCJ0byI6ImRpZDpwb2x5Z29uaWQ6cG9seWdvbjptdW1iYWk6MnFKNjg5a3BvSnhjU3pCNXNBRkp0UHNTQlNySEY1ZHE3MjJCSE1xVVJMIiwiYm9keSI6eyJkaWRfZG9jIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy9ucy9kaWQvdjEiXSwiaWQiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bXVtYmFpOjJxR3lUOG1NR3J2VGpNV0N6VEc4TVhUb2d4anpQVFViMkxra0wzQUoxMSIsInNlcnZpY2UiOlt7ImlkIjoiZGlkOnBvbHlnb25pZDpwb2x5Z29uOm11bWJhaToycUd5VDhtTUdydlRqTVdDelRHOE1YVG9neGp6UFRVYjJMa2tMM0FKMTEjcHVzaCIsInR5cGUiOiJwdXNoLW5vdGlmaWNhdGlvbiIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHBzOi8vcHVzaC1zdGFnaW5nLnBvbHlnb25pZC5jb20vYXBpL3YxIiwibWV0YWRhdGEiOnsiZGV2aWNlcyI6W3siY2lwaGVydGV4dCI6IkMxRU9BNGViOUh6RC9QREtPeHlaazZaYjBaUzlvSlR1RmgyTi8xaTJ3TWxrdFJ4bzhteGJmMnN2Nk14OFl1SGRLbVo4eVJWbE9CSmpqOGRDckxDRHplYjJPREs2ZDVsanN0S05GTUlhOFh6aW1DV2I5eXoyN0h6Tm1EbTJWdGtJQWxaSjB6cEJFdnZlSWNUVVVodmNXeFkzQnVRRnpYdmJHL2lIYnUxcWRkdUh3L3JVMmJoTE9jdDN1bnpXVnB3T1pVYXg5TExTWk9zSGVyR0hZM1JJWUp5ZCtDcVV3TU5DQWJHYlJFcjlUU1pGdU1HbzZ1NGVRSlBOOURGQ09NaXdCdS9UOW5vMTNCZ1NIcDhHSlV6eFc1YTg4Z0FXQUZjVE5hSDVkOUdoamlERXp4NDUyV291Wms0Zloxd1BVd3lPUHJsaCt2QjVDd05jejRpWXNZK0ZPZEFMdDdyRUZ1RWhLZXhCVlp5VmYxckFLUDhOdi83YWtHdCtaWlZJY3RsRHRTUGUwYXpseW9TYTFKVVo2a0JLclJWdmUvL1pWdVRSMm81VHRXN2I2SlJVZ2w2S2IrVEhiN3V1OWlRcDN5ODAvWTVtMXpiSzNyUnlLTjM0U0YwMmpkY2JkZWVoeWNRc1NTMmRscm1oODZ6MWRvUS9XMVlXQ0Zzam1PazNQdnZxVU8rSXRPSnhVYURNcWVlZXE2QldldUxxd01oZE5KRVRBN3BIRzhES1JFdDZZLzNXRlNaOFF0aWdVWU9XQUplVXNHRzh1SFRSeSt3aVVKV1NIcVFTSmZHdXFOakFLa05mVFVYeDNqWmhOYmEveEFtUXV0bkxQQjJpbXowNHNSRFhTUzNYMUFmSnVSdUp6Wk1lTUE3MXM2TEZaS01Iakw4cXBENzI0L21OcEVFPSIsImFsZyI6IlJTQS1PQUVQLTUxMiJ9XX19XX0sIm1lc3NhZ2UiOm51bGwsInNjb3BlIjpbeyJpZCI6MSwiY2lyY3VpdElkIjoiY3JlZGVudGlhbEF0b21pY1F1ZXJ5U2lnVjIiLCJwcm9vZiI6eyJwaV9hIjpbIjE4MjgxMDIzOTY3MTY3MTQ4Mjg0MDc3ODUyNzI1MjU0MzY3MjM3MTQ5Mzc4MDY0MjY1ODIyMDc2OTM3MDQ0NDc5NDE2OTM1NDk1MDE1IiwiMTY0NzkyMzExMjExNDA2NjU4MDc0MTMzOTI1NTIzNzEzMjAxNjcxNTcwOTc5MTIxNjU4NjE5MDk0MDYwNzkzMjYzOTUyOTM5OTUwODIiLCIxIl0sInBpX2IiOltbIjEwOTE5MzU4Njg1NTY1NzQzODkzMzg3Mjk1NjgwNzk0OTY2Njg0OTQ0NjQ1ODQ3OTMyNzI4MDEzMzI1OTgxOTY5MjY4ODk1MTkxMDI2IiwiMjEwMzk4NDgwMTE3Mzc1OTUxMDM0NjYxODQ4MTIyMzI5MDk1NDE4MTAwNDY5NzE4OTY1NjE3ODAwMzg3ODMzODk0NjA2MzkxNTQ5MTMiXSxbIjI1NDUyMzEzNzU3NDU3MDM4OTY0Mzg4NjU4ODEwNjYwMjYzMTg2NzM4NTc4MzQyNDIzNDg0MDc4OTYzMzg4MDE3MjI3MjA3NDIzNzgiLCIxNzE1NTc4OTMxNzg4MDI3MDc3NzUyMDM2OTc1MDM3NzAyODk1NDA1MTQ2OTY2Mzk1MTczMDQxMTkyMzE0NDIwODc4NDQ5MzgyNzYxMSJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNDYxODI0NjU0NzkwMjkzMDE3MTYwMTM5MTUyOTAxNzk5OTMyNjcyOTkyMzUyNzA1MDE4NTAwNTE2OTI5NjUxOTI3NDQ4NTA2OTQ5OCIsIjgyMDg2Njc2OTM0Njg1OTQyMzczMTU2OTY3NjQ2Njg5NTI3MzE3MDk3MjA4Nzc5OTAxMjUyNTgzNDU2MDMwMzIyNjc0NjUzMTQ4MzkiLCIxIl0sInByb3RvY29sIjoiZ3JvdGgxNiIsImN1cnZlIjoiYm4xMjgifSwicHViX3NpZ25hbHMiOlsiMSIsIjIxNDA0MDQxODQxNjkwMTMwOTA4NTk1NTI1NjA1Njk1NjY0OTY4NTAwODc3NjE3MDU2MDY0MjY5MTkyODk1NTQxNTU3NzkzMjgyIiwiMTQxNzI3NzAwODg2MDIyNTU4MjU3MzM2MTEzNjUzOTg3MTg5MzUzNzEyNDQ1NzUyNTMwNTYzNjEzMDc4MjMzMDMwMjg0NDI5MDc5NTAiLCIxIiwiMjc3NTI3NjY4MjMzNzE0NzE0MDgyNDgyMjU3MDg2ODEzMTM3NjQ4NjYyMzE2NTUxODczNjYwNzE4ODEwNzA5MTg5ODQ0NzEwNDIiLCIxIiwiNjczMjk4MjYxNjY0NzgxMTc1NDExOTc5NjE4NjQ3NDI2MTQxNzgxOTM3MDI3NzE4NzI3OTkzMzQ2OTM2MDY0NTE0OTM5NzkzNjAzMiIsIjE2ODIzMzU0OTMiLCIyMTk1Nzg2MTcwNjQ1NDAwMTYyMzQxNjE2NDAzNzU3NTU4NjU0MTIiLCIwIiwiNDc5MjEzMDA3OTQ2MjY4MTE2NTQyODUxMTIwMTI1MzIzNTg1MDAxNTY0ODM1Mjg4MzI0MDU3NzMxNTAyNjQ3Nzc4MDQ5MzExMDY3NSIsIjAiLCIxIiwiNjIyMjQ4NzU0NTgyMTgxMjYxOTMwNTEzNjkwMTc5MDI1MTc3MDM5MDY4NDEwNTI4MTkxNTcxODk5NTY4MjQ5MTkzNzA0MTc1ODc2IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX19.eyJwcm9vZiI6eyJwaV9hIjpbIjc3NjY1ODUzMDg2MjIxMTI5MDQ1MzQ0NjQ2MDY4NTg2NDk2MzUyNTA2MzY5NDQ5NTU0MjQzMTE0MDUzODc0NjkxMDk0MDIzMzM3NTkiLCI1OTc2MDc4NDg2NzExMTUzOTk2OTYzMDQ0NDU5NjY5MzcyNjgwMTgwMjQwNDk4MTgwOTI0ODE3MjE3MTM5NjE4MzMwMDQwMTc0MTIiLCIxIl0sInBpX2IiOltbIjEyMzg2MjU2MTc1Njk4NjIwMTY5ODAxMTMwNDEyNzEyNzgwOTYyNjIwNjY5NzIxNzc1NDcyODQ4OTY2NzEwNzI1MjQ3NjczNDk0NzExIiwiOTk3NTE0NzcyMDc3ODgzNjc1MTE4NDUzMzM0ODUzMDgyMTQ0OTk3MjM4NTUzOTE4NTk0MDUxNTg4Nzk1ODgyMjczMzg1ODQ4Nzk4MCJdLFsiMzI2Njg2MDAwNjYwNzg5ODg1MzQ4NjE3OTg1NTQ4OTA3NDc4Nzg5NjQ2NjQ1ODgyNTM1ODI2OTUxMjAxNTA5MjY3OTEwMzU5NjIwNiIsIjEwMjg0MTc1Nzg2ODM3MTg4MzEzMTQ3ODY5MzY2NTU1MDU1NTMzMDU5NjI4OTUwMDI0ODk5OTAwNzQwNDM4ODYwMTU1ODYxMTM4MjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjEyMDg2ODY2OTk3NjY3NDIwMDg1MDIxNTkwODY4NTA3NjYzNjk3OTQwMjA2MTk1NzQyOTIxNjM1MjI0MzAwODIyMjAzMjkxNTU1NjgyIiwiODM5ODExNDQ3NjE2OTc0NDYyODgzODA0NTE2NDk0NzkxNDA4MDUzOTQ2NjQwNTU5MDU0NzY4NTgyMzI3NzgxMzc3ODk0NDE2ODA1OCIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2IiwiY3VydmUiOiJibjEyOCJ9LCJwdWJfc2lnbmFscyI6WyIyMTQwNDA0MTg0MTY5MDEzMDkwODU5NTUyNTYwNTY5NTY2NDk2ODUwMDg3NzYxNzA1NjA2NDI2OTE5Mjg5NTU0MTU1Nzc5MzI4MiIsIjIwOTQ1MjY4MTg3NDg3NzkzMjI5NDU5NDkwMTk1MzIzMzk3NzY2ODIzNjQwNTU1ODU0NjMxNDI2NDE0MTgyOTU4NDk2Mjg3MTUwMDY4IiwiMTA1MjI5NTY0NzMwODM3MjU4OTA1Nzk2ODUxMjM2NzgyNTYxNzQ5MTMyOTY0MTI5MTIzMDE0MzU0NTIwNjAyOTQ2ODI1MTEzODU0NzMiXX0';

  const opts: VerifyOpts = {
    acceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minutes
    acceptedProofGenerationDelay: 10 * 365 * 24 * 60 * 60 * 1000, // 10 years
  };
  await expect(
    verifier.fullVerify(token, request, opts),
  ).resolves.not.toThrow();
});
