import {
    AUTH_CIRCUIT_ID, AUTHORIZATION_REQUEST_MESSAGE_TYPE,
    AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
    createAuthorizationRequest,
    messageWithZeroKnowledgeProofRequest,
    verifyProofs,
    extractMetadata,
} from './auth.js';

import {
    circuits,
} from './circuits/constants.js';

import {
    ZERO_KNOWLEDGE_PROOF_TYPE,
} from './proofs/zk.js';

beforeAll((done) => done());
afterAll((done) => done());

test('createAuthorizationRequest', () => {
    const challenge = 10;
    const aud = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
    const request = createAuthorizationRequest(challenge, aud, 'https://test.com/callback');
    expect(request.data.scope.length).toEqual(1);
    const proof = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitId: AUTH_CIRCUIT_ID,
        rules: {
            challenge: 12345678,
            countryBlacklist: [840],
            currentYear: 2021,
            currentMonth: 9,
            currentDay: 28,
            minAge: 18,
            audience: aud,
            allowedIssuers: [
                '115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe',
                '115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe',
            ],
        },
    };
    messageWithZeroKnowledgeProofRequest(request, proof);
    expect(request.data.scope.length).toEqual(2);
});

test('TestVerify', async () => {
    const zkpProof = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitId: circuits.KycBySignaturesCircuitID,
        proofData: {
            pi_a: [
                '10441536817202584897377823144827964642356918402871315490038163167310235469676',
                '3188873104904010906845899057040012497857652125001996465924027367142766788060',
                '1',
            ],
            pi_b: [
                [
                    '10259767950868305572343651918722890484304440255374794205464892311274784569874',
                    '18113532891970083775734522192028652126404157383671158241782353379080674688210',
                ], [
                    '20011188305329655231409527762393912898857036946232895893305954758470171745705',
                    '19212224402431449690017436050830610655559646158634403540885275057516508525272',
                ], [
                    '1',
                    '0',
                ],
            ],
            pi_c: [
                '17410066358263445906462947561105622363737416663317734129930901016400750644236',
                '10889346016675221860511647187111664354773325795907973404602900127856769668544',
                '1',
            ],
        },
        pubSignals: [
            '12345',
            '372902514040400364441393275265861152892555341750332828757240276565437644800',
            '19443506635601976434000063402326775248489014592264899338419890539515181882284',
            '840', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0',
            '372902514040400364441393275265861152892555341750332828757240276565437644800',
            '19443506635601976434000063402326775248489014592264899338419890539515181882284',
            '2021', '4', '25',
        ],
    };

    const message = {
        type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
        data: {
            scope: [zkpProof],
        },
    };

    const error = await verifyProofs(message);
    expect(error).toBeNull();
});

test('TestVerifyMessageWithAuthProof', async () => {
    const zkpProof = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitId: circuits.authCircuitId,
        proofData: {
            pi_a: [
                '2370534291294441687575434871070063634049522739054135650290327914016792634144',
                '18704664440065881255248484392571034267692380947539795837185393466696768539729',
                '1',
            ],
            pi_b: [
                [
                    '1593753415597360514506439944675236073038159742598884104707775208490282580641',
                    '15142074894866083200293799148931702287457526593114838706672766340147139402722',
                ], [
                    '19117825221840408597122339519717065920080389822558089367138595722092823743944',
                    '2706264472260224656022451103720565978368804964791420659255319627595448027435',
                ], [
                    '1',
                    '0',
                ],
            ],
            pi_c: [
                '156766304977057264803138092945401446963129379605822159500567538377014916135',
                '10031227231200820171929683445407743402234929438478965985477678284516420821593',
                '1',
            ],
        },
        pubSignals: [
            '1',
            '5816868615164565912277677884704888703982258184820398645933682814085602171910',
            '286312392162647260160287083374160163061246635086990474403590223113720496128',
        ],
    };

    const message = {
        type: AUTHORIZATION_RESPONSE_MESSAGE_TYPE,
        data: {
            scope: [zkpProof],
        },
    };

    const error = await verifyProofs(message);
    expect(error).toBeNull();
    const token = extractMetadata(message);

    expect(token.state).toBe('5816868615164565912277677884704888703982258184820398645933682814085602171910');
    expect(token.id).toBe('113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj');
    expect(token.verifyState(
        'https://ropsten.infura.io/v3/182bafeca1a4413e8608bf34fd3aa873',
        '0x035C4DBC897D203483D942696CE1dF5a9f933FcC'),
    ).toBeTruthy();
});

test('TestVerifyWrongMessage', () => {
    const zkpProof = {
        type: ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitId: circuits.KycBySignaturesCircuitID,
        rules: {},
    };

    const message = {
        type: AUTHORIZATION_REQUEST_MESSAGE_TYPE,
        data: {
            scope: [zkpProof],
        },
    };

    expect(verifyProofs(message)).rejects.toThrow(Error);
});
