/**
 * defines basic metadata that can be retrieved from any proof
 */
export class ProofMetadata {
    constructor(authData) {
        this.authData = authData;
        this.additionalData = { };
    }
}

/**
 * Defines basic metadata that can be retrieved from auth proof
 */
export class AuthenticationMetadata {
    constructor(userIdentifier, userState, authenticationChallenge) {
        this.userIdentifier = userIdentifier;
        this.userState = userState;
        this.authenticationChallenge = authenticationChallenge;
    }
}
