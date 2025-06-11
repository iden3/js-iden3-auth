import { Id } from '@iden3/js-iden3-core';
import { ethers } from 'ethers';
import { ICache } from '@lib/cache';
import { Abi, Abi__factory } from '@lib/state/types/ethers-contracts';
import { IState } from '@lib/state/types/ethers-contracts/Abi';

const ZERO_BIGINT = BigInt(0);

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

export type CacheOptions = {
  stateResolveCache?: ICache<ResolvedState>;
  rootResolveCache?: ICache<ResolvedState>;
};

export class EthStateResolver implements IStateResolver {
  private _contract: Abi;
  private _stateResolveCache?: ICache<ResolvedState>;
  private _rootResolveCache?: ICache<ResolvedState>;

  constructor(rpcUrl: string, contractAddress: string, cacheOptions?: CacheOptions) {
    const url = new URL(rpcUrl);
    const ethersProvider = new ethers.providers.JsonRpcProvider({
      skipFetchSetup: true,
      url: url.href,
      user: url.username,
      password: url.password
    });
    this._contract = Abi__factory.connect(contractAddress, ethersProvider);

    // Initialize cache options
    this._stateResolveCache = cacheOptions?.stateResolveCache;
    this._rootResolveCache = cacheOptions?.rootResolveCache;
  }

  private getCacheKey(id: bigint, state: bigint): string {
    return `${id.toString()}-${state.toString()}`;
  }

  private getRootCacheKey(state: bigint): string {
    return state.toString();
  }

  public async resolve(id: bigint, state: bigint): Promise<ResolvedState> {
    const cacheKey = this.getCacheKey(id, state);

    // Check cache first
    const cachedResult = await this._stateResolveCache?.get(cacheKey);
    if (cachedResult) {
      return cachedResult;
    }

    // Perform the actual resolution
    const result = await this.performResolve(id, state);

    // Cache the result
    await this._stateResolveCache?.set(cacheKey, result);

    return result;
  }

  private async performResolve(id: bigint, state: bigint): Promise<ResolvedState> {
    // check if id is genesis
    const isGenesis = isGenesisStateId(id, state);

    let contractState: IState.StateInfoStructOutput;
    try {
      contractState = await this._contract.getStateInfoByIdAndState(id, state);
    } catch (e) {
      if ((e as { errorArgs: string[] }).errorArgs[0] === 'State does not exist') {
        if (isGenesis) {
          return {
            latest: true,
            genesis: isGenesis,
            state,
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
      if (contractState.replacedAtTimestamp.eq(ZERO_BIGINT)) {
        throw new Error(`no information about state transition`);
      }
      return {
        latest: false,
        genesis: false,
        state,
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
    const cacheKey = this.getRootCacheKey(state);

    // Check cache first
    const cachedResult = await this._rootResolveCache?.get(cacheKey);

    if (cachedResult) {
      console.log('rootResolveCache hit', cacheKey);
      return cachedResult;
    }

    // Perform the actual root resolution
    const result = await this.performRootResolve(state);

    // Cache the result
    await this._rootResolveCache?.set(cacheKey, result);

    return result;
  }

  private async performRootResolve(state: bigint): Promise<ResolvedState> {
    let globalStateInfo: IState.GistRootInfoStructOutput;
    try {
      globalStateInfo = await this._contract.getGISTRootInfo(state);
    } catch (e: unknown) {
      if ((e as { errorArgs: string[] }).errorArgs[0] === 'Root does not exist') {
        throw new Error('GIST root does not exist in the smart contract');
      }
      throw e;
    }

    if (!globalStateInfo.root.eq(state)) {
      throw new Error(`gist info contains invalid state`);
    }

    if (!globalStateInfo.replacedByRoot.eq(ZERO_BIGINT)) {
      if (globalStateInfo.replacedAtTimestamp.eq(ZERO_BIGINT)) {
        throw new Error(`state was replaced, but replaced time unknown`);
      }
      return {
        latest: false,
        state,
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
