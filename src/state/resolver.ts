import { Core } from '../core/core';
import { toLittleEndian } from '../core/util';
import { ethers } from 'ethers';
import { stateABI } from './abi';
import { Id } from '../core/id';

export interface IStateResolver {
  resolve(id: bigint, state: bigint): Promise<ResolvedState>;
}
export type ResolvedState = {
  latest: boolean;
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
    const ethersProvider = new ethers.providers.JsonRpcProvider(this.rpcUrl);
    const contract = new ethers.Contract(
      this.contractAddress,
      stateABI,
      ethersProvider,
    );
    const isGenesis = isGenesisStateId(id, state);
    if (isGenesis) {
      return { latest: true, state, transitionTimestamp: 0 };
    }

    const contractState = await contract.getState(id);

    if (contractState.toBigInt() === 0n) {
      throw new Error('state is not found. Identity is not genesis');
    }

    if (contractState.toBigInt() !== state) {
      const transitionInfo = await contract.getTransitionInfo(contractState);

      if (transitionInfo[5].toBigInt() === 0n) {
        throw new Error('Transition info contains invalid id');
      }

      if (transitionInfo[0].toBigInt() === 0n) {
        throw new Error('No information of transition for non-latest state');
      }

      return {
        latest: false,
        state: state,
        transitionTimestamp: transitionInfo[0].toBigInt(),
      };
    }

    return { latest: true, state, transitionTimestamp: 0 };
  }
}

export function isGenesisStateId(id: bigint, state: bigint): boolean {
  const idBytes = toLittleEndian(id, 31);

  const typeBJP0 = new Uint8Array(2);
  const stateBytes = toLittleEndian(state, 32);
  const idGenesisBytes = stateBytes.slice(-27);

  // we take last 27 bytes, because of swapped endianness
  const idFromStateBytes = Uint8Array.from([
    ...typeBJP0,
    ...idGenesisBytes,
    ...Core.calculateChecksum(typeBJP0, idGenesisBytes),
  ]);

  if (JSON.stringify(idBytes) !== JSON.stringify(idFromStateBytes)) {
    throw new Error(
      `ID from genesis state (${
       (Id.idFromBytes(idBytes).string())
      }) and provided (${(Id.fromBytes(idFromStateBytes)).string()}) don't match`,
    );
  }

  return true;
}
