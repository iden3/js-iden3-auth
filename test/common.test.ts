import { DID } from '@iden3/js-iden3-core';
import { checkUserState } from '@lib/circuits/common';
import { mockResolverWithNoStateInContract, mockResolverWithNotLatesState } from './mocks';
import { Hash } from '@iden3/js-merkletree';

describe('Common', () => {
  const issuerDID = DID.parse('did:iden3:polygon:mumbai:x6suHR8HkEYczV9yVeAKKiXCZAd25P8WS6QvNhszk');
  const issuerID = DID.idFromDID(issuerDID);
  const hash = Hash.fromBigInt(
    BigInt('13483594486393726782589954979757194488582220051583949915340451442108840786819')
  );
  it('checkUserState fails', async () => {
    await expect(
      checkUserState(mockResolverWithNoStateInContract, issuerID, hash)
    ).rejects.toThrow('State is not genesis and not registered in the smart contract');
  });
  it('checkUserState', async () => {
    await checkUserState(mockResolverWithNotLatesState, issuerID, hash);
  });
});
