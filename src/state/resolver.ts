import { Id } from '@iden3/js-iden3-core';
import { ethers } from 'ethers';
import { ICache, createInMemoryCache } from '@lib/cache';
import { Abi, Abi__factory } from '@lib/state/types/ethers-contracts';
import { IState } from '@lib/state/types/ethers-contracts/Abi';
import { CONSTANTS } from '@lib/constants';
import { checkRootDoesNotExistError, checkStateDoesNotExistError } from '@0xpolygonid/js-sdk';

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

/**
 * Configuration options for caching behavior
 */
type ResolverCacheOptions = {
  /** TTL in milliseconds for latest states/roots (shorter since they can change) */
  notReplacedTtl?: number;
  /** TTL in milliseconds for historical states/roots (longer since they're they can change with less probability) */
  replacedTtl?: number;
  /** Maximum number of entries to store in cache */
  maxSize?: number;
};

/**
 * Configuration options for the EthStateResolver
 */
export type ResolverOptions = {
  /** Configuration for state resolution caching */
  stateCacheOptions?: {
    /** Custom cache implementation (if not provided, uses in-memory cache) */
    cache?: ICache<ResolvedState>;
  } & ResolverCacheOptions;
  /** Configuration for GIST root resolution caching */
  rootCacheOptions?: {
    /** Custom cache implementation (if not provided, uses in-memory cache) */
    cache?: ICache<ResolvedState>;
  } & ResolverCacheOptions;
  /** Whether to skip fetch setup for the ethers provider */
  skipFetchSetup?: boolean;
};

/**
 * Ethereum-based state resolver that resolves identity states and GIST roots
 * from a smart contract deployed on an Ethereum-compatible blockchain.
 *
 * This resolver caches results with different TTL values:
 * - Latest states/roots: shorter TTL since they can transition to historical
 * - Historical states/roots: longer TTL since they are immutable once replaced
 */
export class EthStateResolver implements IStateResolver {
  private _contract: Abi;
  private _stateResolveCache: ICache<ResolvedState>;
  private _rootResolveCache: ICache<ResolvedState>;
  private _stateCacheOptions: Required<ResolverCacheOptions>;
  private _rootCacheOptions: Required<ResolverCacheOptions>;

  /**
   * Creates a new EthStateResolver instance
   * @param rpcUrl - The RPC URL for the Ethereum-compatible blockchain
   * @param contractAddress - The address of the state contract
   * @param options - Optional configuration for caching and provider setup
   */
  constructor(rpcUrl: string, contractAddress: string, options?: ResolverOptions) {
    const url = new URL(rpcUrl);
    const ethersProvider = new ethers.providers.JsonRpcProvider({
      skipFetchSetup: options?.skipFetchSetup ?? false,
      url: url.href,
      user: url.username || undefined,
      password: url.password || undefined
    });
    this._contract = Abi__factory.connect(contractAddress, ethersProvider);

    // Store cache options for later use
    this._stateCacheOptions = {
      notReplacedTtl:
        options?.stateCacheOptions?.notReplacedTtl ?? CONSTANTS.ACCEPTED_STATE_TRANSITION_DELAY / 2,
      replacedTtl:
        options?.stateCacheOptions?.replacedTtl ?? CONSTANTS.ACCEPTED_STATE_TRANSITION_DELAY,
      maxSize: options?.stateCacheOptions?.maxSize ?? CONSTANTS.DEFAULT_CACHE_MAX_SIZE
    };
    this._rootCacheOptions = {
      replacedTtl:
        options?.rootCacheOptions?.replacedTtl ?? CONSTANTS.ACCEPTED_STATE_TRANSITION_DELAY,
      notReplacedTtl:
        options?.rootCacheOptions?.notReplacedTtl ?? CONSTANTS.ACCEPTED_STATE_TRANSITION_DELAY / 2,
      maxSize: options?.rootCacheOptions?.maxSize ?? CONSTANTS.DEFAULT_CACHE_MAX_SIZE
    };

    // Initialize cache instances
    this._stateResolveCache =
      options?.stateCacheOptions?.cache ??
      createInMemoryCache({
        maxSize: this._stateCacheOptions.maxSize,
        ttl: this._stateCacheOptions.replacedTtl
      });

    this._rootResolveCache =
      options?.rootCacheOptions?.cache ??
      createInMemoryCache({
        maxSize: this._rootCacheOptions.maxSize,
        ttl: this._rootCacheOptions.replacedTtl
      });
  }

  private getCacheKey(id: bigint, state: bigint): string {
    return `${id.toString()}-${state.toString()}`;
  }

  private getRootCacheKey(root: bigint): string {
    return root.toString();
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

    // Cache the result with appropriate TTL based on whether it's latest or historical
    const ttl =
      result.transitionTimestamp === 0
        ? this._stateCacheOptions.notReplacedTtl
        : this._stateCacheOptions.replacedTtl;

    await this._stateResolveCache?.set(cacheKey, result, ttl);

    return result;
  }

  private async performResolve(id: bigint, state: bigint): Promise<ResolvedState> {
    // check if id is genesis
    const isGenesis = isGenesisStateId(id, state);

    let contractState: IState.StateInfoStructOutput;
    try {
      contractState = await this._contract.getStateInfoByIdAndState(id, state);
    } catch (e) {
      if (checkStateDoesNotExistError(e)) {
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
      if (contractState.replacedAtTimestamp.eq(0n)) {
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

  public async rootResolve(root: bigint): Promise<ResolvedState> {
    const cacheKey = this.getRootCacheKey(root);

    // Check cache first
    const cachedResult = await this._rootResolveCache?.get(cacheKey);

    if (cachedResult) {
      return cachedResult;
    }

    // Perform the actual root resolution
    const result = await this.performRootResolve(root);

    // Cache the result with appropriate TTL based on whether it's latest or historical
    const ttl = result.latest
      ? this._rootCacheOptions.notReplacedTtl
      : this._rootCacheOptions.replacedTtl;

    await this._rootResolveCache?.set(cacheKey, result, ttl);

    return result;
  }

  private async performRootResolve(root: bigint): Promise<ResolvedState> {
    let globalStateInfo: IState.GistRootInfoStructOutput;
    try {
      globalStateInfo = await this._contract.getGISTRootInfo(root);
    } catch (e: unknown) {
      if (checkRootDoesNotExistError(e)) {
        throw new Error('GIST root does not exist in the smart contract');
      }
      throw e;
    }

    if (!globalStateInfo.root.eq(root)) {
      throw new Error(`gist info contains invalid state`);
    }

    if (!globalStateInfo.replacedByRoot.eq(0n)) {
      if (globalStateInfo.replacedAtTimestamp.eq(0n)) {
        throw new Error(`state was replaced, but replaced time unknown`);
      }
      return {
        latest: false,
        state: root,
        transitionTimestamp: globalStateInfo.replacedAtTimestamp.toString(),
        genesis: false
      };
    }

    return {
      latest: true,
      state: root,
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
