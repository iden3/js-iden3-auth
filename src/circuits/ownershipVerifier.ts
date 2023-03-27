import { Id, DID } from '@iden3/js-iden3-core';

export abstract class IDOwnershipPubSignals {
  userId: Id;
  challenge: bigint;
  async verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    const userDID = DID.parseFromId(this.userId);

    if (sender !== userDID.toString()) {
      throw new Error(
        `sender is not used for proof creation, expected ${sender}, user from public signals: ${this.userId.string()}`,
      );
    }
    if (challenge !== this.challenge) {
      throw new Error(
        `challenge is not used for proof creation, expected ${challenge}, challenge from public signals: ${this.challenge}  `,
      );
    }
  }
}
