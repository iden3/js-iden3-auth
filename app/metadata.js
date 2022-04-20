import { Circuits } from "./circuits.js"
import { challengeAttribute, identifierAttribute, stateAttribute, zeroKnowledgeProofType } from "./constants.js"


/**
 *  ExtractMetadata extracts proof metadata
 */
function ExtractMetadata(metadata) {
    if (metadata.type !== zeroKnowledgeProofType) {
        throw new Error(`Proofs type ${metadata.type} is not zeroknowledge`)
    }
    const circuit = Circuits.getCircuit(metadata.circuitId)
    if (!circuit) {
        throw new Error(`Circuit with id ${metadata.circuitId} not found`)
    }
    const proofData = parsePublicSignals(metadata.PubSignals, circuit.GetPublicSignalsSchema())
    return proofData;
}

/**
 * 
 * @param {[]string} signals 
 * @param {[]byte} schema 
 * @returns {ProofMetadata}
 */
function parsePublicSignals(signals, schema) {
    const proofMetadata = new ProofMetadata();

    const metaData = JSON.parse(schema);

    const identifierIndex = metaData[identifierAttribute];
    if (!identifierIndex) {
        throw new Error("No user identifier attribute in provided proof");
    }
    const stateIndex = metaData[stateAttribute];
    if (stateIndex) {
        proofMetadata.authData.userState = signals[stateIndex];
    }
    const challengeIndex = metaData[challengeAttribute];
    if (!challengeIndex) {
        throw new Error("No user challenge attribute in provided proof")
    }

    proofMetadata.authData.userIdentifier = convertID(signals[identifierIndex])

    proofMetadata.authData.authenticationChallenge = signals[challengeIndex]

    Object.keys(metaData)
        .filter(k => ![identifierAttribute, challengeAttribute].includes(k))
        .forEach(k => proofMetadata.AdditionalData[k] = signals[metaData[k]])

    return proofMetadata;
}

