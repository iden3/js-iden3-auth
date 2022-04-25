import { Core } from '../core/core.js';
import { verifyState } from '../state.js';

export class UserToken {
    /**
     *
     * @param {*} id
     * @param {*} challenge
     * @param {*} state
     * @param {*} scope
     */
    constructor(id, challenge, state, scope) { }

    update(scopeId, metadata) {
        const {
            authenticationChallenge,
            userIdentifier,
            userState,
        } = metadata.authData;

        if (this.challenge !== authenticationChallenge) {
            throw new Error('Different challenges were used for authentication');
        }
        if (this.id !== userIdentifier) {
            throw new Error('Different identifiers were used for authentication');
        }

        // TODO: make a decision if (each proof must contain user state
        if (!this.state && userState) {
            this.state = userState;
        }

        this.challenge = authenticationChallenge;
        this.id = userIdentifier;

        if (metadata.AdditionalData) {
            this.scope[scopeId] = metadata.AdditionalData;
        }
    }

    async verifyState(url, addr) {
        const id = Core.idFromString(this.id);

        const stateBigInt = BigInt(this.state);

        return await verifyState(url, addr, id.BigInt(), stateBigInt);
    }
}


// Name represents name of the service
const name = 'authorization-service';
const protocolName = 'https://iden3-communication.io';
// AuthorizationRequestMessageType defines auth request type of the communication protocol
const authorizationRequestMessageType = protocolName + '/authorization-request/v1';
// AuthorizationResponseMessageType defines auth response type of the communication protocol
const authorizationResponseMessageType = protocolName + '/authorization-response/v1';


/**
 *
 * @param {types.Message} message
 * @return {UserToken} token
 */
function ExtractMetadata(message) {
    if (message.type !== authorizationResponseMessageType) {
        throw new Error(`${name} doesn't support {message.type} message type`);
    }
    let authorizationResponseData;

    switch (message.type) {
        // TODO
        case 'rawJSON':
            authorizationResponseData = JSON.parse(message.data);
        case 'AuthorizationMessageResponseData':
            authorizationResponseData = JSON.parse(message.data);
    }

    //     const  token =  new UserToken();
    //     token.scope = {}
    //    Object.keys(authorizationResponseData.scope).forEach(k => {
    //        let typedScope =
    //    })
    //     for _, s := range authorizationResponseData.Scope {

    //         var typedScope types.TypedScope
    //         typedScope, err = toTypedScope(s)
    //         if err != nil {
    //             return nil, err
    //         }
    //         switch proof := typedScope.(type) {
    // 		case types.ZeroKnowledgeProof:
    //             err = zeroknowledge.ExtractMetadata(& proof)
    //             if err != nil {
    //                 throw new Error("proof with type  %s is not valid. %s", proof.Type, err.Error())
    //             }
    //             err = token.Update(string(proof.CircuitID), proof.ProofMetadata)

    //             if err != nil {
    //                 throw new Error("can't provide user token %s", err.Error())
    //             }

    // 		case types.SignatureProof:
    //             err = signature.ExtractMetadata(& proof)
    //             if err != nil {
    //                 throw new Error("proof with type  %s is not valid. %s", proof.Type, err.Error())
    //             }
    //             err = token.Update(proof.KeyType, proof.ProofMetadata)
    //             if err != nil {
    //                 throw new Error("can't provide user token %s", err.Error())
    //             }
    //         }
    //     }
    //     return token, nil
}

/**
 *
 * @param {*} value
 * @return {TypedScope} TypedScope
 */
function toTypedScope(value) {
    // switch obj := value.(type) {
    // case map[string]interface{ }:
    //     scopeMap, ok := value.(map[string]interface{})
    //     if !ok {
    //         return nil, errors.New("scope object is not a map")
    //     }
    //     b, err := json.Marshal(value)
    //     if err != nil {
    //         return nil, errors.Wrap(err, "can't marshall scope obj")
    //     }
    //     switch types.ProofType(scopeMap["type"].(string)) {
    //         case types.ZeroKnowledgeProofType:
    //             var zkp types.ZeroKnowledgeProof
    //             err = json.Unmarshal(b, & zkp)
    //             if err != nil {
    //                 return nil, errors.Wrap(err, "can't unmarshall to zkp proof")
    //             }
    //             return zkp, nil
    //         case types.SignatureProofType:
    //             var sig types.SignatureProof
    //             err = json.Unmarshal(b, & sig)
    //             if err != nil {
    //                 return nil, errors.Wrap(err, "can't unmarshall to signature proof")
    //             }
    //             return sig, nil
    //         default:
    //             return nil, errors.Errorf("proof type is not supported: %s ", scopeMap["type"])
    //     }
    // case types.TypedScope:
    //     return obj, nil
    // default:
    //     return nil, errors.Errorf("scope object type is not supported %v", value)
    // }
}
