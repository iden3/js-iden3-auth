import { DID } from '@iden3/js-iden3-core';
import { isGenesisStateId } from '@lib/state/resolver';

test('isGenesisState', async () => {
  const userDID =
    'did:iden3:polygon:mumbai:x6suHR8HkEYczV9yVeAKKiXCZAd25P8WS6QvNhszk';
  const userID = DID.parse(userDID);

  const genesisState =
    '7521024223205616003431860562270429547098131848980857190502964780628723574810';
  const nonGenesisState =
    '6017654403209798611575982337826892532952335378376369712724079246845524041042';

  let isGenesis = isGenesisStateId(userID.id.bigInt(), BigInt(genesisState));
  expect(isGenesis).toEqual(true);

  isGenesis = isGenesisStateId(userID.id.bigInt(), BigInt(nonGenesisState));
  expect(isGenesis).toEqual(false);
});
