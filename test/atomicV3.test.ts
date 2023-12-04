import { Verifier, createAuthorizationRequestWithMessage } from '@lib/auth/auth';
import { testOpts, resolvers } from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  CircuitId,
  ZeroKnowledgeProofRequest
} from '@0xpolygonid/js-sdk';

describe('atomicV3', () => {
  it('TestVerifyV3MessageWithSigProof_NonMerkalized', async () => {
    const verifierID = 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7';
    const callbackURL = 'https://test.com/callback';
    const reason = 'test';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 84239,
      circuitId: CircuitId.AtomicQueryV3,
      optional: true,
      query: {
        allowedIssuers: ['*'],
        credentialSubject: {
          documentType: {
            $eq: 99
          }
        },
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
        type: 'KYCAgeCredential',
        proofType: 'BJJSignature2021'
      }
    };

    const request = createAuthorizationRequestWithMessage(
      reason,
      'message to sign',
      verifierID,
      callbackURL
    );
    request.body.scope.push(proofRequest);

    const userID = 'did:polygonid:polygon:mumbai:2qJhHewUsGr2UbX1nu5uvL3Pcb5bsCyjmY13qDGhuE';
    const responseUUID = '4f3549b-0c9d-47f8-968c-c9b0c10b8847';

    // response
    const message: AuthorizationResponseMessage = {
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      from: userID,
      to: verifierID,
      id: responseUUID,
      thid: request.thid,
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: proofRequest.circuitId,
            proof: {
              pi_a: [
                '19496124686330960109178567457994500715090428735141622232991930923571239526973',
                '5333382355311367091450878440766577869910107382042895327170027939018771173693',
                '1'
              ],
              pi_b: [
                [
                  '11389510010457944981784369226495937314782550305095522991941726775120463234015',
                  '148126783179791025484328164821355776079627478790636761838003498405312298491'
                ],
                [
                  '7766703297362633966237582659363417860563792628606295958222132892597495153529',
                  '15738672081296050965904031242799997034543496978611262556741337726708555978459'
                ],
                ['1', '0']
              ],
              pi_c: [
                '18760918093552542394351420933759316824980816755792571030066979459092260184974',
                '9182463283752601046486968329887492781236172359540910031526604279260097167801',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '24350193136522144674198915615287261666057484215399963613273196208778187266',
              '6878827749334423177867070513976817969741918647989708554257988220056800690399',
              '0',
              '0',
              '0',
              '1',
              '84239',
              '23438740603785224800206716785431987755756056895444592546615136461203837442',
              '1',
              '6878827749334423177867070513976817969741918647989708554257988220056800690399',
              '1699623999',
              '198285726510688200335207273836123338699',
              '1',
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
              '22728440853100433399211827098349696449620101147489499428101651758549307906',
              '39'
            ]
          }
        ]
      }
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized', async () => {
    const verifierID = 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7';
    const callbackURL = 'https://test.com/callback';
    const reason = 'test';

    const proofRequest: ZeroKnowledgeProofRequest = {
      id: 84239,
      circuitId: CircuitId.AtomicQueryV3,
      optional: true,
      query: {
        allowedIssuers: ['did:polygonid:polygon:mumbai:2qLvkstQ79ysCXmgF3gwLRPmG3zu87FUvHdWXuCaR2'],
        credentialSubject: {
          ZKPexperiance: {
            $eq: true
          }
        },
        context:
          'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
        type: 'KYCEmployee',
        proofType: 'Iden3SparseMerkleTreeProof'
      }
    };

    const request = createAuthorizationRequestWithMessage(
      reason,
      'message to sign',
      verifierID,
      callbackURL
    );
    request.body.scope.push(proofRequest);

    const userID = 'did:polygonid:polygon:mumbai:2qJhHewUsGr2UbX1nu5uvL3Pcb5bsCyjmY13qDGhuE';
    const responseUUID = '4f3549b-0c9d-47f8-968c-c9b0c10b8847';

    const message: AuthorizationResponseMessage = {
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
      from: userID,
      to: verifierID,
      id: responseUUID,
      thid: request.thid,
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: proofRequest.circuitId,
            proof: {
              pi_a: [
                '12582436427083471416912726376269523958753392889886772648509670943923737162680',
                '13327685963399967454789624389844881269242234911288664890636268436523860633770',
                '1'
              ],
              pi_b: [
                [
                  '6693358487464199858877518294886808672471333730867991644283194148737940896450',
                  '11110843334777774682940947357404229242113193200057722521711019357322069752377'
                ],
                [
                  '18992402416017831847078005062147848393652749581766372802125889248754111439905',
                  '11455962363724404420777607059394249791464317126303291781963911144873696870341'
                ],
                ['1', '0']
              ],
              pi_c: [
                '2893633285249011673439519599661172218147608584996899953922116448566272374939',
                '9838181085566977797835840019736511974884393723532541789371781527381359846654',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '24350193136522144674198915615287261666057484215399963613273196208778187266',
              '8780491001938472632986532064321434471309522823142095150913966547706097373753',
              '0',
              '0',
              '0',
              '2',
              '84239',
              '23438740603785224800206716785431987755756056895444592546615136461203837442',
              '1',
              '8780491001938472632986532064321434471309522823142095150913966547706097373753',
              '1699624368',
              '219578617064540016234161640375755865412',
              '0',
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
              '22728440853100433399211827098349696449620101147489499428101651758549307906',
              '39'
            ]
          }
        ]
      }
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });
});
