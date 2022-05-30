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

var verificationKeyLoader: FSKeyLoader = new FSKeyLoader('./data');
var schemaLoader: ISchemaLoader = new UniversalSchemaLoader('ipfs.io');

class MockResolver implements IStateResolver {
  resolve(id: bigint, state: bigint): Promise<ResolvedState> {
    throw { latest: true };
  }
}
var mockStateResolver: MockResolver = new MockResolver();

// test('createAuthorizationRequest', () => {
//   const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const callback = 'https://test.com/callback';
//   const request: AuthorizationRequestMessage = createAuthorizationRequest(
//     'kyc age verification',
//     sender,
//     callback,
//   );
//   expect(request.body.scope.length).toEqual(0);
//   expect(request.body.callbackUrl).toEqual(callback);
//   expect(request.body.callbackUrl).toEqual(callback);
//   expect(request.from).toEqual(sender);

//   const proofRequest: ZKPRequest = {
//     id: 24,
//     circuit_id: 'credentialAtomicQueryMTP',
//     rules: {
//       challenge: 84239,
//       query: {
//         allowedIssuers: '1195GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLN9',
//         schema: {
//           type: 'KYCAgeCredential',
//           url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
//         },
//         req: {
//           birthday: {
//             $lt: 20000101,
//           },
//         },
//       },
//     },
//   };
//   request.body.scope.push(proofRequest);
//   expect(request.body.scope.length).toEqual(1);
// });

// test('TestVerifyMessageWithoutProoof', async () => {
//   const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const userId = '1135GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const callback = 'https://test.com/callback';
//   const msg = 'message to sign';
//   const request: AuthorizationRequestMessage =
//     createAuthorizationRequestWithMessage(
//       'kyc verification',
//       msg,
//       sender,
//       callback,
//     );

//   const response: AuthorizationResponseMessage = {
//     id: uuidv4(),
//     thid: request.thid,
//     typ: request.typ,
//     type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
//     from: userId,
//     to: sender,
//     body: {
//       message: request.body.message,
//       scope: [],
//     },
//   };

//   let verifier = new Verifier(
//     verificationKeyLoader,
//     schemaLoader,
//     mockStateResolver,
//   );

//   expect(await verifier.verifyAuthResponse(response, request)).not.toThrow();
// });

// test('TestVerifyWithAtomicMTPProof', async () => {
//   const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const callback = 'https://test.com/callback';
//   const userId = '1135GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const request: AuthorizationRequestMessage = createAuthorizationRequest(
//     'kyc verification',
//     sender,
//     callback,
//   );
//   expect(request.body.scope.length).toEqual(0);
//   expect(request.body.callbackUrl).toEqual(callback);
//   expect(request.body.reason).toEqual(callback);
//   expect(request.from).toEqual(sender);

//   const proofRequest: ZKPRequest = {
//     id: 24,
//     circuit_id: 'credentialAtomicQueryMTP',
//     rules: {
//       query: {
//         allowedIssuers: ['*'],
//         schema: {
//           type: 'KYCCountryOfResidenceCredential',
//           url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
//         },
//         req: {
//           countryCode: {
//             $nin: [840, 120, 340, 509],
//           },
//         },
//       },
//     },
//   };
//   request.body.scope.push(proofRequest);

//   expect(request.body.scope.length).toEqual(1);

//   const mtpProof: ZKPResponse = {
//     id: proofRequest.id,
//     circuit_id: 'credentialAtomicQueryMTP',
//     proof_data: {
//       pi_a: [
//         '20973485107186613835294420504168844900060429745180277370078136645423323796988',
//         '20876512355517454358387352357430469269532511208427702435640954212414846794988',
//         '1',
//       ],
//       pi_b: [
//         [
//           '15359787792291301524429511563163819833209670586891499149880103897821631812320',
//           '952148097741318750401406678248864482408113418728045541853254838790211944557',
//         ],
//         [
//           '3866547068988378419787216494850441937393748849859411619995030091666678234233',
//           '12737260954983772047680437941193675886215315463965099527215354428856166589220',
//         ],
//         ['1', '0'],
//       ],
//       pi_c: [
//         '14032051669376519932957072147382739134658885782661390170658631107795386034990',
//         '3426651920168576141328466441385872894824417141788260830832563707950605034542',
//         '1',
//       ],
//       protocol: 'groth16',
//       curve: 'bn128',
//     },
//     pub_signals: [
//       '227999792560601581143923121210388382198276828932112237742319153709274234880',
//       '10099789665300975457802178862296098271243359660315802759495016285352640212814',
//       '12345',
//       '8390795654739203972616926774091445498451520813142121365678565136228528725312',
//       '206811791431269707427589302274952473147879888022142096363950465656014110720',
//       '1653057062',
//       '106590880073303418818490710639556704462',
//       '2',
//       '4',
//       '840',
//       '120',
//       '340',
//       '509',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//     ],
//   };

//   const response: AuthorizationResponseMessage = {
//     id: uuidv4(),
//     thid: request.thid,
//     typ: request.typ,
//     type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
//     from: userId,
//     to: sender,
//     body: {
//       message: request.body.message,
//       scope: [mtpProof],
//     },
//   };

//   let verifier = new Verifier(
//     verificationKeyLoader,
//     schemaLoader,
//     mockStateResolver,
//   );

//   expect(await verifier.verifyAuthResponse(response, request)).not.toThrow();
// });

// test('TestVerifyJWZ', async () => {
//   const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const callback = 'https://test.com/callback';
//   const userId = '1135GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const request: AuthorizationRequestMessage = createAuthorizationRequest(
//     'kyc verification',
//     sender,
//     callback,
//   );
//   expect(request.body.scope.length).toEqual(0);
//   expect(request.body.callbackUrl).toEqual(callback);
//   expect(request.body.reason).toEqual(callback);
//   expect(request.from).toEqual(sender);

//   const proofRequest: ZKPRequest = {
//     id: 24,
//     circuit_id: 'credentialAtomicQueryMTP',
//     rules: {
//       query: {
//         allowedIssuers: ['*'],
//         schema: {
//           type: 'KYCCountryOfResidenceCredential',
//           url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
//         },
//         req: {
//           countryCode: {
//             $nin: [840, 120, 340, 509],
//           },
//         },
//       },
//     },
//   };
//   request.body.scope.push(proofRequest);

//   expect(request.body.scope.length).toEqual(1);

//   const mtpProof: ZKPResponse = {
//     id: proofRequest.id,
//     circuit_id: 'credentialAtomicQueryMTP',
//     proof_data: {
//       pi_a: [
//         '20973485107186613835294420504168844900060429745180277370078136645423323796988',
//         '20876512355517454358387352357430469269532511208427702435640954212414846794988',
//         '1',
//       ],
//       pi_b: [
//         [
//           '15359787792291301524429511563163819833209670586891499149880103897821631812320',
//           '952148097741318750401406678248864482408113418728045541853254838790211944557',
//         ],
//         [
//           '3866547068988378419787216494850441937393748849859411619995030091666678234233',
//           '12737260954983772047680437941193675886215315463965099527215354428856166589220',
//         ],
//         ['1', '0'],
//       ],
//       pi_c: [
//         '14032051669376519932957072147382739134658885782661390170658631107795386034990',
//         '3426651920168576141328466441385872894824417141788260830832563707950605034542',
//         '1',
//       ],
//       protocol: 'groth16',
//       curve: 'bn128',
//     },
//     pub_signals: [
//       '227999792560601581143923121210388382198276828932112237742319153709274234880',
//       '10099789665300975457802178862296098271243359660315802759495016285352640212814',
//       '12345',
//       '8390795654739203972616926774091445498451520813142121365678565136228528725312',
//       '206811791431269707427589302274952473147879888022142096363950465656014110720',
//       '1653057062',
//       '106590880073303418818490710639556704462',
//       '2',
//       '4',
//       '840',
//       '120',
//       '340',
//       '509',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//     ],
//   };

//   const response: AuthorizationResponseMessage = {
//     id: uuidv4(),
//     thid: request.thid,
//     typ: request.typ,
//     type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
//     from: userId,
//     to: sender,
//     body: {
//       message: request.body.message,
//       scope: [mtpProof],
//     },
//   };

//   let verifier = new Verifier(
//     verificationKeyLoader,
//     schemaLoader,
//     mockStateResolver,
//   );
//   request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
//   request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

//   let token =
//     'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNDEyNDM2MTk3NDk0NDc5NTg3Mzk2NjY3Mzg1NzA3MzY4MjgyNTY4MDU1MTE4MjY5ODY0NDU3OTI3NDc2OTkwNjM2NDE5NzAyNDUxIiwiMTA3ODE3MzkwOTU0NDUyMDE5OTY0Njc0MTQ4MTc5NDE4MDU4Nzk5ODI0MTA2NzYzODYxNzY4NDUyOTYzNzYzNDQ5ODUxODc2NjMzMzQiLCIxIl0sInBpX2IiOltbIjE4MDY3ODY4NzQwMDA2MjI1NjE1NDQ3MTk0NDcxMzcwNjU4OTgwOTk5OTI2MzY5Njk1MjkzMTE1NzEyOTUxMzY2NzA3NzQ0MDY0NjA2IiwiMjE1OTkyNDE1NzA1NDc3MzEyMzQzMDQwMzk5ODkxNjY0MDY0MTU4OTk3MTc2NTkxNzE3NjAwNDM4OTk1MDkxNTIwMTE0Nzk2NjM3NTciXSxbIjY2OTk1NDA3MDUwNzQ5MjQ5OTc5NjcyNzUxODYzMjQ3NTU0NDIyNjA2MDc2NzE1MzY0MzQ0MDMwNjU1MjkxNjQ3Njk3MDI0NzczOTgiLCIxMTI1NzY0MzI5MzIwMTYyNzQ1MDI5MzE4NTE2NDI4ODQ4MjQyMDU1OTgwNjY0OTkzNzM3MTU2ODE2MDc0MjYwMTM4NjY3MTY1OTgwMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNjIxNjQyMzUwMzI4OTQ5NjI5Mjk0NDA1MjAzMjE5MDM1MzYyNTQyMjQxMTQ4MzM4MzM3ODk3OTAyOTY2NzI0Mzc4NTMxOTIwODA5NSIsIjE0ODE2MjE4MDQ1MTU4Mzg4NzU4NTY3NjA4NjA1NTc2Mzg0OTk0MzM5NzE0MzkwMzcwMzAwOTYzNTgwNjU4Mzg2NTM0MTU4NjAzNzExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNDk3Njk0Mzk0Mzk2NjM2NTA2MjEyMzIyMTk5OTgzODAxMzE3MTIyODE1NjQ5NTM2NjI3MDM3NzI2MTM4MDQ0OTc4Nzg3MTg5ODY3MiIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19';

//   expect(await verifier.verifyJWZ(token, request)).not.toThrow();
// });

// test('TestFullVerify', async () => {
//   const sender = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const callback = 'https://test.com/callback';
//   const userId = '1135GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
//   const request: AuthorizationRequestMessage = createAuthorizationRequest(
//     'kyc verification',
//     sender,
//     callback,
//   );
//   expect(request.body.scope.length).toEqual(0);
//   expect(request.body.callbackUrl).toEqual(callback);
//   expect(request.body.reason).toEqual(callback);
//   expect(request.from).toEqual(sender);

//   const proofRequest: ZKPRequest = {
//     id: 24,
//     circuit_id: 'credentialAtomicQueryMTP',
//     rules: {
//       query: {
//         allowedIssuers: ['*'],
//         schema: {
//           type: 'KYCCountryOfResidenceCredential',
//           url: 'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v2.json-ld',
//         },
//         req: {
//           countryCode: {
//             $nin: [840, 120, 340, 509],
//           },
//         },
//       },
//     },
//   };
//   request.body.scope.push(proofRequest);

//   expect(request.body.scope.length).toEqual(1);

//   const mtpProof: ZKPResponse = {
//     id: proofRequest.id,
//     circuit_id: 'credentialAtomicQueryMTP',
//     proof_data: {
//       pi_a: [
//         '20973485107186613835294420504168844900060429745180277370078136645423323796988',
//         '20876512355517454358387352357430469269532511208427702435640954212414846794988',
//         '1',
//       ],
//       pi_b: [
//         [
//           '15359787792291301524429511563163819833209670586891499149880103897821631812320',
//           '952148097741318750401406678248864482408113418728045541853254838790211944557',
//         ],
//         [
//           '3866547068988378419787216494850441937393748849859411619995030091666678234233',
//           '12737260954983772047680437941193675886215315463965099527215354428856166589220',
//         ],
//         ['1', '0'],
//       ],
//       pi_c: [
//         '14032051669376519932957072147382739134658885782661390170658631107795386034990',
//         '3426651920168576141328466441385872894824417141788260830832563707950605034542',
//         '1',
//       ],
//       protocol: 'groth16',
//       curve: 'bn128',
//     },
//     pub_signals: [
//       '227999792560601581143923121210388382198276828932112237742319153709274234880',
//       '10099789665300975457802178862296098271243359660315802759495016285352640212814',
//       '12345',
//       '8390795654739203972616926774091445498451520813142121365678565136228528725312',
//       '206811791431269707427589302274952473147879888022142096363950465656014110720',
//       '1653057062',
//       '106590880073303418818490710639556704462',
//       '2',
//       '4',
//       '840',
//       '120',
//       '340',
//       '509',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//       '0',
//     ],
//   };

//   const response: AuthorizationResponseMessage = {
//     id: uuidv4(),
//     thid: request.thid,
//     typ: request.typ,
//     type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
//     from: userId,
//     to: sender,
//     body: {
//       message: request.body.message,
//       scope: [mtpProof],
//     },
//   };

//   let verifier = new Verifier(
//     verificationKeyLoader,
//     schemaLoader,
//     mockStateResolver,
//   );
//   request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
//   request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542'; // because it's used in the response

//   let token =
//     'eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aCIsImNyaXQiOlsiY2lyY3VpdElkIl0sInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIn0.eyJpZCI6IjI4NDk0MDA3LTljNDktNGYxYS05Njk0LTc3MDBjMDg4NjViZiIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zY29tbS1wbGFpbi1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiI3ZjM4YTE5My0wOTE4LTRhNDgtOWZhYy0zNmFkZmRiOGI1NDIiLCJib2R5Ijp7Im1lc3NhZ2UiOiJtZXNzYWdlIHRvIHNpZ24iLCJzY29wZSI6W3siaWQiOjEsImNpcmN1aXRfaWQiOiJjcmVkZW50aWFsQXRvbWljUXVlcnlNVFAiLCJwcm9vZiI6eyJwaV9hIjpbIjIwOTczNDg1MTA3MTg2NjEzODM1Mjk0NDIwNTA0MTY4ODQ0OTAwMDYwNDI5NzQ1MTgwMjc3MzcwMDc4MTM2NjQ1NDIzMzIzNzk2OTg4IiwiMjA4NzY1MTIzNTU1MTc0NTQzNTgzODczNTIzNTc0MzA0NjkyNjk1MzI1MTEyMDg0Mjc3MDI0MzU2NDA5NTQyMTI0MTQ4NDY3OTQ5ODgiLCIxIl0sInBpX2IiOltbIjE1MzU5Nzg3NzkyMjkxMzAxNTI0NDI5NTExNTYzMTYzODE5ODMzMjA5NjcwNTg2ODkxNDk5MTQ5ODgwMTAzODk3ODIxNjMxODEyMzIwIiwiOTUyMTQ4MDk3NzQxMzE4NzUwNDAxNDA2Njc4MjQ4ODY0NDgyNDA4MTEzNDE4NzI4MDQ1NTQxODUzMjU0ODM4NzkwMjExOTQ0NTU3Il0sWyIzODY2NTQ3MDY4OTg4Mzc4NDE5Nzg3MjE2NDk0ODUwNDQxOTM3MzkzNzQ4ODQ5ODU5NDExNjE5OTk1MDMwMDkxNjY2Njc4MjM0MjMzIiwiMTI3MzcyNjA5NTQ5ODM3NzIwNDc2ODA0Mzc5NDExOTM2NzU4ODYyMTUzMTU0NjM5NjUwOTk1MjcyMTUzNTQ0Mjg4NTYxNjY1ODkyMjAiXSxbIjEiLCIwIl1dLCJwaV9jIjpbIjE0MDMyMDUxNjY5Mzc2NTE5OTMyOTU3MDcyMTQ3MzgyNzM5MTM0NjU4ODg1NzgyNjYxMzkwMTcwNjU4NjMxMTA3Nzk1Mzg2MDM0OTkwIiwiMzQyNjY1MTkyMDE2ODU3NjE0MTMyODQ2NjQ0MTM4NTg3Mjg5NDgyNDQxNzE0MTc4ODI2MDgzMDgzMjU2MzcwNzk1MDYwNTAzNDU0MiIsIjEiXSwicHJvdG9jb2wiOiJncm90aDE2In0sInB1Yl9zaWduYWxzIjpbIjIyNzk5OTc5MjU2MDYwMTU4MTE0MzkyMzEyMTIxMDM4ODM4MjE5ODI3NjgyODkzMjExMjIzNzc0MjMxOTE1MzcwOTI3NDIzNDg4MCIsIjEwMDk5Nzg5NjY1MzAwOTc1NDU3ODAyMTc4ODYyMjk2MDk4MjcxMjQzMzU5NjYwMzE1ODAyNzU5NDk1MDE2Mjg1MzUyNjQwMjEyODE0IiwiMTIzNDUiLCI4MzkwNzk1NjU0NzM5MjAzOTcyNjE2OTI2Nzc0MDkxNDQ1NDk4NDUxNTIwODEzMTQyMTIxMzY1Njc4NTY1MTM2MjI4NTI4NzI1MzEyIiwiMjA2ODExNzkxNDMxMjY5NzA3NDI3NTg5MzAyMjc0OTUyNDczMTQ3ODc5ODg4MDIyMTQyMDk2MzYzOTUwNDY1NjU2MDE0MTEwNzIwIiwiMTY1MzA1NzA2MiIsIjEwNjU5MDg4MDA3MzMwMzQxODgxODQ5MDcxMDYzOTU1NjcwNDQ2MiIsIjIiLCI0IiwiODQwIiwiMTIwIiwiMzQwIiwiNTA5IiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIiwiMCIsIjAiLCIwIl19XX0sImZyb20iOiIxMTl0cWNlV2RSZDJGNlduQXlWdUZRUkZqSzNXVVhxMkxvclNQeUc5TEoiLCJ0byI6IjExMjVHSnFndzZZRXNLRndqNjNHWTg3TU14UEw5a3dES3hQVWl3TUxOWiJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwNDEyNDM2MTk3NDk0NDc5NTg3Mzk2NjY3Mzg1NzA3MzY4MjgyNTY4MDU1MTE4MjY5ODY0NDU3OTI3NDc2OTkwNjM2NDE5NzAyNDUxIiwiMTA3ODE3MzkwOTU0NDUyMDE5OTY0Njc0MTQ4MTc5NDE4MDU4Nzk5ODI0MTA2NzYzODYxNzY4NDUyOTYzNzYzNDQ5ODUxODc2NjMzMzQiLCIxIl0sInBpX2IiOltbIjE4MDY3ODY4NzQwMDA2MjI1NjE1NDQ3MTk0NDcxMzcwNjU4OTgwOTk5OTI2MzY5Njk1MjkzMTE1NzEyOTUxMzY2NzA3NzQ0MDY0NjA2IiwiMjE1OTkyNDE1NzA1NDc3MzEyMzQzMDQwMzk5ODkxNjY0MDY0MTU4OTk3MTc2NTkxNzE3NjAwNDM4OTk1MDkxNTIwMTE0Nzk2NjM3NTciXSxbIjY2OTk1NDA3MDUwNzQ5MjQ5OTc5NjcyNzUxODYzMjQ3NTU0NDIyNjA2MDc2NzE1MzY0MzQ0MDMwNjU1MjkxNjQ3Njk3MDI0NzczOTgiLCIxMTI1NzY0MzI5MzIwMTYyNzQ1MDI5MzE4NTE2NDI4ODQ4MjQyMDU1OTgwNjY0OTkzNzM3MTU2ODE2MDc0MjYwMTM4NjY3MTY1OTgwMCJdLFsiMSIsIjAiXV0sInBpX2MiOlsiNjIxNjQyMzUwMzI4OTQ5NjI5Mjk0NDA1MjAzMjE5MDM1MzYyNTQyMjQxMTQ4MzM4MzM3ODk3OTAyOTY2NzI0Mzc4NTMxOTIwODA5NSIsIjE0ODE2MjE4MDQ1MTU4Mzg4NzU4NTY3NjA4NjA1NTc2Mzg0OTk0MzM5NzE0MzkwMzcwMzAwOTYzNTgwNjU4Mzg2NTM0MTU4NjAzNzExIiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYifSwicHViX3NpZ25hbHMiOlsiNDk3Njk0Mzk0Mzk2NjM2NTA2MjEyMzIyMTk5OTgzODAxMzE3MTIyODE1NjQ5NTM2NjI3MDM3NzI2MTM4MDQ0OTc4Nzg3MTg5ODY3MiIsIjE4NjU2MTQ3NTQ2NjY2OTQ0NDg0NDUzODk5MjQxOTE2NDY5NTQ0MDkwMjU4ODEwMTkyODAzOTQ5NTIyNzk0NDkwNDkzMjcxMDA1MzEzIiwiMzc5OTQ5MTUwMTMwMjE0NzIzNDIwNTg5NjEwOTExMTYxODk1NDk1NjQ3Nzg5MDA2NjQ5Nzg1MjY0NzM4MTQxMjk5MTM1NDE0MjcyIl19';

//   expect(await verifier.fullVerify(token, request)).not.toThrow();
// });

test('registry: get existing circuit', () => {
  const type = Circuits.getCircuitPubSignals('auth');
  const instance = new type(['1','5816868615164565912277677884704888703982258184820398645933682814085602171910','286312392162647260160287083374160163061246635086990474403590223113720496128']);
  expect(type).not.toBeNull();
  expect(instance).not.toBeNull();
  expect(instance.verifyQuery).not.toBeNull();
  expect((instance as AuthPubSignals).challenge.toString()).toEqual('1');
  expect((instance as AuthPubSignals).userId.string()).toEqual('113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj');
  expect((instance as AuthPubSignals).userState.toString()).toEqual('5816868615164565912277677884704888703982258184820398645933682814085602171910');

});
