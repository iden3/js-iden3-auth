import {
    AUTH_CIRCUIT_ID,
    ZERO_KNOWLEDGE_PROOF_TYPE,
    createAuthorizationRequest,
    messageWithZeroKnowledgeProofRequest,
    verifyProofs
} from './auth.js';

import {
    authorizationResponseMessageType,
} from './circuits/token.js';

import {
    circuits,
} from './circuits/constants.js';

test('test createAuthorizationRequest', () => {
    const challenge = 10;
    const aud       = '1125GJqgw6YEsKFwj63GY87MMxPL9kwDKxPUiwMLNZ';
    const request   = createAuthorizationRequest(challenge, aud, 'https://test.com/callback');
    expect(request.data.scope.length).toEqual(1);
    const proof = {
        type     : ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitID: AUTH_CIRCUIT_ID,
        rules    : {
            challenge       : 12345678,
            countryBlacklist: [840],
            currentYear     : 2021,
            currentMonth    : 9,
            currentDay      : 28,
            minAge          : 18,
            audience        : aud,
            allowedIssuers  : [
                '115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe',
                '115zTGHKvFeFLPu3vF9Wx2gBqnxGnzvTpmkHPM2LCe',
            ],
        },
    };
    messageWithZeroKnowledgeProofRequest(request, proof);
    expect(request.data.scope.length).toEqual(2);
});

test('test verifyProofs', () => {
    const zkpProof = {
        type      : ZERO_KNOWLEDGE_PROOF_TYPE,
        circuitID : circuits.KycBySignaturesCircuitID,
        proofData : {
            A: [
                "10441536817202584897377823144827964642356918402871315490038163167310235469676",
                "3188873104904010906845899057040012497857652125001996465924027367142766788060",
                "1"
            ],
            B: [["10259767950868305572343651918722890484304440255374794205464892311274784569874",
                "18113532891970083775734522192028652126404157383671158241782353379080674688210",
            ], [
                "20011188305329655231409527762393912898857036946232895893305954758470171745705",
                "19212224402431449690017436050830610655559646158634403540885275057516508525272",
            ], [
                "1",
                "0",
            ]],
            C: ["17410066358263445906462947561105622363737416663317734129930901016400750644236",
                "10889346016675221860511647187111664354773325795907973404602900127856769668544",
                "1",
            ],
        },
        pubSignals: ["12345", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "840", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "372902514040400364441393275265861152892555341750332828757240276565437644800", "19443506635601976434000063402326775248489014592264899338419890539515181882284", "2021", "4", "25"],
    };

    const message = {
        type: authorizationResponseMessageType,
        data: {
            scope: [zkpProof],
        },
    };

    const error = verifyProofs(message);

    expect(error).toBeNull();
});
