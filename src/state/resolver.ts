import { Id } from '@iden3/js-iden3-core';
import { ethers } from 'ethers';
import { Abi__factory } from './types/ethers-contracts';
import { IState } from './types/ethers-contracts/Abi';

const zeroInt = BigInt(0);

export type Resolvers = {
  [key: string]: IStateResolver;
};

export interface IStateResolver {
  resolve(id: bigint, state: bigint): Promise<ResolvedState>;
  rootResolve(state: bigint): Promise<ResolvedState>;
}
export type ResolvedState = {
  latest: boolean;
  genesis: boolean;
  state: unknown;
  transitionTimestamp: number | string;
};
export class EthStateResolver implements IStateResolver {
  private rpcUrl: string;
  private contractAddress: string;

  constructor(rpcUrl: string, contractAddress: string) {
    this.rpcUrl = rpcUrl;
    this.contractAddress = contractAddress;
  }

  public async resolve(id: bigint, state: bigint): Promise<ResolvedState> {
    const url = new URL(this.rpcUrl);
    const ethersProvider = new ethers.providers.JsonRpcProvider({
      url: url.href,
      user: url.username,
      password: url.password
    });
    const contract = Abi__factory.connect(this.contractAddress, ethersProvider);

    // check if id is genesis
    const isGenesis = isGenesisStateId(id, state);

    let contractState: IState.StateInfoStructOutput;
    try {
      contractState = await contract.getStateInfoByIdAndState(id, state);
    } catch (e) {
      if ((e as { errorArgs: string[] }).errorArgs[0] === 'State does not exist') {
        if (isGenesis) {
          return {
            latest: true,
            genesis: isGenesis,
            state: state,
            transitionTimestamp: 0
          };
        }
        throw new Error('State is not genesis and not registered in the smart contract');
      }
      throw e;
    }

    if (!contractState.id.eq(id)) {
      throw new Error(`state was recorded for another identity`);
    }

    if (!contractState.state.eq(state)) {
      if (contractState.replacedAtTimestamp.eq(zeroInt)) {
        throw new Error(`no information about state transition`);
      }
      return {
        latest: false,
        genesis: false,
        state: state,
        transitionTimestamp: contractState.replacedAtTimestamp.toNumber()
      };
    }

    return {
      latest: contractState.replacedAtTimestamp.isZero(),
      genesis: isGenesis,
      state,
      transitionTimestamp: contractState.replacedAtTimestamp.toNumber()
    };
  }

  public async rootResolve(state: bigint): Promise<ResolvedState> {
    const url = new URL(this.rpcUrl);
    const ethersProvider = new ethers.providers.JsonRpcProvider({
      url: url.href,
      user: url.username,
      password: url.password
    });
    const contract = Abi__factory.connect(this.contractAddress, ethersProvider);

    let globalStateInfo: IState.GistRootInfoStructOutput;
    try {
      globalStateInfo = await contract.getGISTRootInfo(state);
    } catch (e: unknown) {
      if ((e as { errorArgs: string[] }).errorArgs[0] === 'Root does not exist') {
        throw new Error('GIST root does not exist in the smart contract');
      }
      throw e;
    }

    if (!globalStateInfo.root.eq(state)) {
      throw new Error(`gist info contains invalid state`);
    }

    if (!globalStateInfo.replacedByRoot.eq(zeroInt)) {
      if (globalStateInfo.replacedAtTimestamp.eq(zeroInt)) {
        throw new Error(`state was replaced, but replaced time unknown`);
      }
      return {
        latest: false,
        state: state,
        transitionTimestamp: globalStateInfo.replacedAtTimestamp.toString(),
        genesis: false
      };
    }

    return {
      latest: true,
      state: state,
      transitionTimestamp: 0,
      genesis: false
    };
  }
}

export function isGenesisStateId(id: bigint, state: bigint): boolean {
  const userID = Id.fromBigInt(id);
  const identifier = Id.idGenesisFromIdenState(userID.type(), state);
  return userID.equal(identifier);
}
