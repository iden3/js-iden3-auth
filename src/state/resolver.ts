import { Core } from '../core/core';
import { toLittleEndian } from '../core/util';
import { ethers } from 'ethers';
import { stateABI } from './abi';

export interface IStateResolver {
  resolve(id: bigint, state: bigint): Promise<ResolvedState>;
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
    const contract = new ethers.Contract(
      this.contractAddress,
      stateABI,
      ethersProvider,
    );
    // check if id is genesis
    const isGenesis = isGenesisStateId(id, state);

    // get latest state of identity from contract
    const contractState = await contract.getState(id);

    if (contractState.toBigInt() === 0n) {
      if (!isGenesis) {
        throw new Error(
          'identity state is not genesis and state not found on-chain',
        );
      }
      return {
        latest: true,
        genesis: isGenesis,
        state: state,
        transitionTimestamp: 0,
      };
    }

    if (contractState.toBigInt() !== state) {
      const transitionInfo = await contract.getTransitionInfo(state);

      if (transitionInfo[4].toBigInt() === 0n) {
        throw new Error('Transition info contains invalid id');
      }

      if (transitionInfo[0].toBigInt() === 0n) {
        throw new Error('No information of transition for non-latest state');
      }

      return {
        latest: false,
        state: state,
        genesis: isGenesis,
        transitionTimestamp: transitionInfo[0].toBigInt(),
      };
    }

    return { latest: true, genesis: isGenesis, state, transitionTimestamp: 0 };
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
    return false;
  }

  return true;
}
