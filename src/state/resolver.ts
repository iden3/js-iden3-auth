import { Id, Blockchain, buildDIDType, DidMethod, NetworkId } from '@iden3/js-iden3-core';
import { ethers } from 'ethers';
import { Abi__factory } from '@lib/state/types/ethers-contracts';

const zeroInt = BigInt(0);

export interface IStateResolver {
  resolve(id: bigint, state: bigint): Promise<ResolvedState>;
  rootResolve(state: bigint): Promise<ResolvedState>;
}
export type ResolvedState = {
  latest: boolean;
  genesis: boolean;
  state: any;
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
      password: url.password,
    });
    const contract = Abi__factory.connect(this.contractAddress, ethersProvider);

    // check if id is genesis
    const isGenesis = isGenesisStateId(id, state);

    // get latest state of identity from contract
    const contractState = await contract.getStateInfoById(id);

    if (contractState.state.eq(zeroInt)) {
      if (!isGenesis) {
        throw new Error(
          'state is not genesis and not registered in the smart contract',
        );
      }
      return {
        latest: true,
        genesis: isGenesis,
        state: state,
        transitionTimestamp: 0,
      };
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
        transitionTimestamp: contractState.replacedAtTimestamp.toString(),
      };
    }

    return { latest: true, genesis: isGenesis, state, transitionTimestamp: 0 };
  }

  public async rootResolve(state: bigint): Promise<ResolvedState> {
    const url = new URL(this.rpcUrl);
    const ethersProvider = new ethers.providers.JsonRpcProvider({
      url: url.href,
      user: url.username,
      password: url.password,
    });
    const contract = Abi__factory.connect(this.contractAddress, ethersProvider);

    const globalStateInfo = await contract.getGISTRootInfo(state);

    if (globalStateInfo.createdAtTimestamp.eq(zeroInt)) {
      throw new Error(`gist state doesn't exists in contract`);
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
        genesis: false,
      };
    }

    return {
      latest: true,
      state: state,
      transitionTimestamp: 0,
      genesis: false,
    };
  }
}

export function isGenesisStateId(id: bigint, state: bigint): boolean {
  const didType = buildDIDType(
    DidMethod.Iden3,
    Blockchain.Polygon,
    NetworkId.Mumbai,
  );

  const genesisId = Id.idGenesisFromIdenState(didType, state);

  return id.toString() === genesisId.bigInt().toString();
}
