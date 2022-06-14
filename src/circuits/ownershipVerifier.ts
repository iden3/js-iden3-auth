import { Id } from '@app/core/id';

export abstract class IDOwnershipPubSignals {
  userId: Id;
  challenge: bigint;
  async verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    if (sender !== this.userId.string()) {
      throw new Error(
        `sender is not used for proof creation, expected ${sender}, user from public signals: ${this.userId.string()}  `,
      );
    }
    if (challenge.toString() !== this.challenge.toString()) {
      throw new Error(
        `challenge is not used for proof creation, expected ${challenge}, challenge from public signals: ${this.challenge.toString()}  `,
      );
    }
  }
}
