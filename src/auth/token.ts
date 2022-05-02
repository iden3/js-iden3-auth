import { ProofMetadata } from './../models/models';
import { Id } from '../core/id';
import { verifyState } from '../state/state';

export class UserToken {
  constructor(
    public id: string = '',
    public challenge: number = 0,
    public userState = '',
    public scope = {},
  ) {}

  update(scopeId: string, metadata: ProofMetadata): void {
    const { authenticationChallenge, userIdentifier, userState } =
      metadata.authData;

    if (this.challenge && this.challenge !== authenticationChallenge) {
      throw new Error('Different challenges were used for authentication');
    }

    if (this.id && this.id !== userIdentifier) {
      throw new Error('Different identifiers were used for authentication');
    }

    // TODO: make a decision if (each proof must contain user state
    if (!this.userState && userState) {
      this.userState = userState;
    }

    this.challenge = authenticationChallenge;
    this.id = userIdentifier;

    if (metadata.additionalData) {
      this.scope[scopeId] = metadata.additionalData;
    }
  }

  async verifyState(
    url: string,
    addr: string,
  ): Promise<{
    latest: boolean;
    state: any;
    transition_timestamp: number | string;
  }> {
    return await verifyState(
      url,
      addr,
      Id.idFromString(this.id).bigInt(),
      this.userState,
    );
  }
}
