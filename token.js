import { Core } from './core/core.js';
import { verifyState } from './state.js';

export class UserToken {
    /**
     *
     * @param {*} id
     * @param {*} challenge
     * @param {*} state
     * @param {*} scope
     */
    constructor(id, challenge, state, scope) {
        this.id = id;
        this.challenge = challenge;
        this.state = state;
        this.scope = scope;
    }

    update(scopeId, metadata) {
        const {
            authenticationChallenge,
            userIdentifier,
            userState,
        } = metadata.authData;

        if (!this.challenge && this.challenge !== authenticationChallenge) {
            throw new Error('Different challenges were used for authentication');
        }
        if (!this.id && this.id !== userIdentifier) {
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
