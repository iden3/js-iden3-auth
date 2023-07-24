import { Id, DID, Constants } from '@iden3/js-iden3-core';
import { sha256 } from 'cross-sha256';

export abstract class IDOwnershipPubSignals {
  userId: Id;
  challenge: bigint;
  async verifyIdOwnership(sender: string, challenge: bigint): Promise<void> {
    let userDid: DID;
    try {
      userDid = DID.parseFromId(this.userId);
    } catch (err: unknown) {
      if ((err as Error).message.includes(Constants.ERRORS.UNKNOWN_DID_METHOD.message)) {
        const senderHashedId = IDOwnershipPubSignals.idFromUnsupportedDID(sender);
        if (senderHashedId.string() !== this.userId.string()) {
          throw new Error(
            `sender is not used for proof creation, expected ${senderHashedId.string()}, user from public signals: ${this.userId.string()}`
          );
        }
        return;
      }
      throw err;
    }

    if (sender !== userDid.string()) {
      throw new Error(
        `sender is not used for proof creation, expected ${sender}, user from public signals: ${userDid.string()}`
      );
    }
    if (challenge !== this.challenge) {
      throw new Error(
        `challenge is not used for proof creation, expected ${challenge}, challenge from public signals: ${this.challenge}  `
      );
    }
  }
  static idFromUnsupportedDID(did: string): Id {
    const hash = Uint8Array.from(new sha256().update(did).digest());

    const genesis = new Uint8Array(27);
    const idSlice = hash.slice(hash.length - 27);
    for (let i = 0; i < genesis.length; i++) {
      genesis[i] = idSlice[i] ?? 0;
    }
    const tp = Uint8Array.from([0b11111111, 0b11111111]);
    return new Id(tp, genesis);
  }
}
