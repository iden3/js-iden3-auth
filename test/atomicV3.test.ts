import { Verifier, createAuthorizationRequestWithMessage } from '@lib/auth/auth';
import { testOpts, resolvers } from './mocks';
import path from 'path';
import {
  AuthorizationResponseMessage,
  PROTOCOL_CONSTANTS,
  CircuitId,
  ZeroKnowledgeProofRequest,
  AuthorizationRequestMessage
} from '@0xpolygonid/js-sdk';

describe('atomicV3', () => {
  it('TestVerifyV3MessageWithSigProof_NonMerklized', async () => {
    const request: AuthorizationRequestMessage = {
      id: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            optional: true,
            query: {
              allowedIssuers: ['*'],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-nonmerklized.jsonld',
              credentialSubject: { documentType: { $eq: 99 } },
              proofType: 'BJJSignature2021',
              type: 'KYCAgeCredential'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    // response
    const message: AuthorizationResponseMessage = {
      id: '59fbefd2-39ce-4346-94f1-49ec86141ba9',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '28b15cd4-3aa1-4ddc-88a3-c05a0f788065',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            proof: {
              pi_a: [
                '15208931239306667614189217356426367087296508213411046833716711442163868780112',
                '20490648944065703271613941501811057996992005137106581261392868037192830801319',
                '1'
              ],
              pi_b: [
                [
                  '9658837325736932089175519161219586340790605854199431170964132439402760343882',
                  '2229712957417570067219766417050901639838551011053815708957384652110672096636'
                ],
                [
                  '8001092431519117455354797520811940294780537362771012429305941024017334317686',
                  '14862879727984936294040948959940841120433831193863247939940900720892674782281'
                ],
                ['1', '0']
              ],
              pi_c: [
                '10979201893913563932568403855542624651100292054247823659266571152101750130209',
                '21286864035525845180147694216456377751365547090829007463506610939813242720910',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '0',
              '22466018227912887497595444357663749526852544754809814096731120723497783810',
              '7232286365358812826682228661780467195854751779823604018938921042558237169817',
              '0',
              '0',
              '0',
              '1',
              '84239',
              '26675680708205250151451142983868154544835349648265874601395279235340702210',
              '1',
              '7232286365358812826682228661780467195854751779823604018938921042558237169817',
              '1702457100',
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
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qFXWZVHKTaYX1vmTGtStgRq1s8vUWhQ7HLjtqb2fV',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });

  it('TestVerifyV3MessageWithMtpProof_Merklized', async () => {
    const request = {
      id: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/request',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        callbackUrl: 'https://test.com/callback',
        reason: 'test',
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            optional: true,
            query: {
              allowedIssuers: [
                'did:polygonid:polygon:mumbai:2qKKc4jxAhabrdFrAF3iC7boycfdQmWXq2qTBU4sPc'
              ],
              context:
                'https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v101.json-ld',
              credentialSubject: { ZKPexperiance: { $eq: true } },
              proofType: 'Iden3SparseMerkleTreeProof',
              type: 'KYCEmployee'
            }
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const message: AuthorizationResponseMessage = {
      id: 'a8ceddf8-24c8-4797-bb94-234a17c6b551',
      typ: PROTOCOL_CONSTANTS.MediaType.PlainMessage,
      type: 'https://iden3-communication.io/authorization/1.0/response',
      thid: '7e5b5847-b479-4499-90ee-5fe4826a5bdd',
      body: {
        message: 'message to sign',
        scope: [
          {
            id: 84239,
            circuitId: 'credentialAtomicQueryV3',
            proof: {
              pi_a: [
                '2191675399003747228361650328748147195525067334657244384911902711268678817802',
                '19948479904115663964234685946314006853666845209972027887002197866333362304394',
                '1'
              ],
              pi_b: [
                [
                  '422189606437031219571968003421368368386938453003241975855652752251201163758',
                  '9263822572774254449054388930060153687464515712228765747368750307969672340141'
                ],
                [
                  '19293339395101879017873172109004141351276884864694548105955158013357482683356',
                  '2779213239514041287265984937924693652347623320831272361142245115033321578990'
                ],
                ['1', '0']
              ],
              pi_c: [
                '3805936274754036854895936107504061566835912493410231954955974762213052034636',
                '11817318886045212940702535466395270095280111730105021796772613798925818134104',
                '1'
              ],
              protocol: 'groth16'
            },
            pub_signals: [
              '1',
              '22466018227912887497595444357663749526852544754809814096731120723497783810',
              '16501727979801979045409842472064689783782600072880560178348889772807800718289',
              '0',
              '0',
              '0',
              '2',
              '84239',
              '26675680708205250151451142983868154544835349648265874601395279235340702210',
              '1',
              '16501727979801979045409842472064689783782600072880560178348889772807800718289',
              '1702457550',
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
              '0'
            ]
          }
        ]
      },
      from: 'did:polygonid:polygon:mumbai:2qFXWZVHKTaYX1vmTGtStgRq1s8vUWhQ7HLjtqb2fV',
      to: 'did:polygonid:polygon:mumbai:2qEevY9VnKdNsVDdXRv3qSLHRqoMGMRRdE5Gmc6iA7'
    };

    const authInstance = await Verifier.newVerifier({
      stateResolver: resolvers,
      circuitsDir: path.join(__dirname, './testdata')
    });

    await authInstance.verifyAuthResponse(message, request, testOpts);
  });
});
