import { Id } from './id';

const method = 'iden3';

// Blockchain is a ledger kind eth / polygon,...
export enum Blockchain {
  Ethereum = 'eth',
  Polygon = 'polygon',
}

// NetworkId is a specific network identifier eth {main, ropsten, rinkeby, kovan}
export enum NetworkId {
  Main = 'main', // mainnet
  Test = 'test', // testnet
  Roptsen = 'ropsten',
  Rinkeby = 'rinkeby',
  Kovan = 'kovan',
  Mumbai = 'mumbai',
}
const didRegex = new RegExp(
  `^did:iden3:((eth|polygon):(main|test|ropsten|rinkeby|kovan):)?[1-9a-km-zA-HJ-NP-Z]{41,42}$`,
);
const errDoesNotMatchRegexp = new Error('did does not match regex');

// DID Decentralized Identifiers (DIDs)
// https://w3c.github.io/did-core/#did-syntax
export class DID {
  id: Id; // Id did specific id
  
  constructor(idStr: string, public blockchain?: Blockchain, public networkId?: NetworkId) {
    if (!!blockchain && !Object.values(Blockchain).includes(blockchain)) {
      throw 'unknown blockhain';
    }
    if (!!networkId && !Object.values(NetworkId).includes(networkId)) {
      throw 'unknown network id';
    }

    this.blockchain = blockchain;
    this.networkId = networkId;
    this.id = Id.idFromString(idStr);
  }
  toString() {
    return `did:${method}:${this.blockchain}:${
      this.networkId
    }:${this.id.string()}`;
  }

  static parseDid(didStr: string) {
    const valid = didRegex.test(didStr);

    if (!valid) {
      throw errDoesNotMatchRegexp;
    }

    const parts = didStr.split(':');

    switch (parts.length) {
      case 3:
        // some did:{method}:{id}
        return new DID(Id.idFromString(parts[2]).string());
      case 5:
        // some did:{method}:{id}:{blockchain}:{networkId}
        return new DID(
          Id.idFromString(parts[4]).string(),
          parts[2] as Blockchain,
          parts[3] as NetworkId,
        );
      default:
        throw new Error('did format is not supported');
    }
  }
}
