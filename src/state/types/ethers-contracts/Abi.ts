/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */
import type {
  BaseContract,
  BigNumber,
  BigNumberish,
  BytesLike,
  CallOverrides,
  ContractTransaction,
  Overrides,
  PopulatedTransaction,
  Signer,
  utils,
} from 'ethers';
import type {
  FunctionFragment,
  Result,
  EventFragment,
} from '@ethersproject/abi';
import type { Listener, Provider } from '@ethersproject/providers';
import type {
  TypedEventFilter,
  TypedEvent,
  TypedListener,
  OnEvent,
  PromiseOrValue,
} from './common';

export declare namespace IState {
  export type GistProofStruct = {
    root: PromiseOrValue<BigNumberish>;
    existence: PromiseOrValue<boolean>;
    siblings: PromiseOrValue<BigNumberish>[];
    index: PromiseOrValue<BigNumberish>;
    value: PromiseOrValue<BigNumberish>;
    auxExistence: PromiseOrValue<boolean>;
    auxIndex: PromiseOrValue<BigNumberish>;
    auxValue: PromiseOrValue<BigNumberish>;
  };

  export type GistProofStructOutput = [
    BigNumber,
    boolean,
    BigNumber[],
    BigNumber,
    BigNumber,
    boolean,
    BigNumber,
    BigNumber,
  ] & {
    root: BigNumber;
    existence: boolean;
    siblings: BigNumber[];
    index: BigNumber;
    value: BigNumber;
    auxExistence: boolean;
    auxIndex: BigNumber;
    auxValue: BigNumber;
  };

  export type GistRootInfoStruct = {
    root: PromiseOrValue<BigNumberish>;
    replacedByRoot: PromiseOrValue<BigNumberish>;
    createdAtTimestamp: PromiseOrValue<BigNumberish>;
    replacedAtTimestamp: PromiseOrValue<BigNumberish>;
    createdAtBlock: PromiseOrValue<BigNumberish>;
    replacedAtBlock: PromiseOrValue<BigNumberish>;
  };

  export type GistRootInfoStructOutput = [
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
  ] & {
    root: BigNumber;
    replacedByRoot: BigNumber;
    createdAtTimestamp: BigNumber;
    replacedAtTimestamp: BigNumber;
    createdAtBlock: BigNumber;
    replacedAtBlock: BigNumber;
  };

  export type StateInfoStruct = {
    id: PromiseOrValue<BigNumberish>;
    state: PromiseOrValue<BigNumberish>;
    replacedByState: PromiseOrValue<BigNumberish>;
    createdAtTimestamp: PromiseOrValue<BigNumberish>;
    replacedAtTimestamp: PromiseOrValue<BigNumberish>;
    createdAtBlock: PromiseOrValue<BigNumberish>;
    replacedAtBlock: PromiseOrValue<BigNumberish>;
  };

  export type StateInfoStructOutput = [
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
    BigNumber,
  ] & {
    id: BigNumber;
    state: BigNumber;
    replacedByState: BigNumber;
    createdAtTimestamp: BigNumber;
    replacedAtTimestamp: BigNumber;
    createdAtBlock: BigNumber;
    replacedAtBlock: BigNumber;
  };
}

export interface AbiInterface extends utils.Interface {
  functions: {
    'VERSION()': FunctionFragment;
    'acceptOwnership()': FunctionFragment;
    'getGISTProof(uint256)': FunctionFragment;
    'getGISTProofByBlock(uint256,uint256)': FunctionFragment;
    'getGISTProofByRoot(uint256,uint256)': FunctionFragment;
    'getGISTProofByTime(uint256,uint256)': FunctionFragment;
    'getGISTRoot()': FunctionFragment;
    'getGISTRootHistory(uint256,uint256)': FunctionFragment;
    'getGISTRootHistoryLength()': FunctionFragment;
    'getGISTRootInfo(uint256)': FunctionFragment;
    'getGISTRootInfoByBlock(uint256)': FunctionFragment;
    'getGISTRootInfoByTime(uint256)': FunctionFragment;
    'getStateInfoById(uint256)': FunctionFragment;
    'getStateInfoByIdAndState(uint256,uint256)': FunctionFragment;
    'getStateInfoHistoryById(uint256,uint256,uint256)': FunctionFragment;
    'getStateInfoHistoryLengthById(uint256)': FunctionFragment;
    'getVerifier()': FunctionFragment;
    'idExists(uint256)': FunctionFragment;
    'initialize(address)': FunctionFragment;
    'owner()': FunctionFragment;
    'pendingOwner()': FunctionFragment;
    'renounceOwnership()': FunctionFragment;
    'setVerifier(address)': FunctionFragment;
    'stateExists(uint256,uint256)': FunctionFragment;
    'transferOwnership(address)': FunctionFragment;
    'transitState(uint256,uint256,uint256,bool,uint256[2],uint256[2][2],uint256[2])': FunctionFragment;
  };

  getFunction(
    nameOrSignatureOrTopic:
      | 'VERSION'
      | 'acceptOwnership'
      | 'getGISTProof'
      | 'getGISTProofByBlock'
      | 'getGISTProofByRoot'
      | 'getGISTProofByTime'
      | 'getGISTRoot'
      | 'getGISTRootHistory'
      | 'getGISTRootHistoryLength'
      | 'getGISTRootInfo'
      | 'getGISTRootInfoByBlock'
      | 'getGISTRootInfoByTime'
      | 'getStateInfoById'
      | 'getStateInfoByIdAndState'
      | 'getStateInfoHistoryById'
      | 'getStateInfoHistoryLengthById'
      | 'getVerifier'
      | 'idExists'
      | 'initialize'
      | 'owner'
      | 'pendingOwner'
      | 'renounceOwnership'
      | 'setVerifier'
      | 'stateExists'
      | 'transferOwnership'
      | 'transitState',
  ): FunctionFragment;

  encodeFunctionData(functionFragment: 'VERSION', values?: undefined): string;
  encodeFunctionData(
    functionFragment: 'acceptOwnership',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTProof',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTProofByBlock',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTProofByRoot',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTProofByTime',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRoot',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRootHistory',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRootHistoryLength',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRootInfo',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRootInfoByBlock',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getGISTRootInfoByTime',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getStateInfoById',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getStateInfoByIdAndState',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getStateInfoHistoryById',
    values: [
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
    ],
  ): string;
  encodeFunctionData(
    functionFragment: 'getStateInfoHistoryLengthById',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'getVerifier',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'idExists',
    values: [PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'initialize',
    values: [PromiseOrValue<string>],
  ): string;
  encodeFunctionData(functionFragment: 'owner', values?: undefined): string;
  encodeFunctionData(
    functionFragment: 'pendingOwner',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'renounceOwnership',
    values?: undefined,
  ): string;
  encodeFunctionData(
    functionFragment: 'setVerifier',
    values: [PromiseOrValue<string>],
  ): string;
  encodeFunctionData(
    functionFragment: 'stateExists',
    values: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
  ): string;
  encodeFunctionData(
    functionFragment: 'transferOwnership',
    values: [PromiseOrValue<string>],
  ): string;
  encodeFunctionData(
    functionFragment: 'transitState',
    values: [
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<BigNumberish>,
      PromiseOrValue<boolean>,
      [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      [
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      ],
      [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
    ],
  ): string;

  decodeFunctionResult(functionFragment: 'VERSION', data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: 'acceptOwnership',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTProof',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTProofByBlock',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTProofByRoot',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTProofByTime',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRoot',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRootHistory',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRootHistoryLength',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRootInfo',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRootInfoByBlock',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getGISTRootInfoByTime',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getStateInfoById',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getStateInfoByIdAndState',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getStateInfoHistoryById',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getStateInfoHistoryLengthById',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'getVerifier',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(functionFragment: 'idExists', data: BytesLike): Result;
  decodeFunctionResult(functionFragment: 'initialize', data: BytesLike): Result;
  decodeFunctionResult(functionFragment: 'owner', data: BytesLike): Result;
  decodeFunctionResult(
    functionFragment: 'pendingOwner',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'renounceOwnership',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'setVerifier',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'stateExists',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'transferOwnership',
    data: BytesLike,
  ): Result;
  decodeFunctionResult(
    functionFragment: 'transitState',
    data: BytesLike,
  ): Result;

  events: {
    'Initialized(uint8)': EventFragment;
    'OwnershipTransferStarted(address,address)': EventFragment;
    'OwnershipTransferred(address,address)': EventFragment;
    'StateUpdated(uint256,uint256,uint256,uint256)': EventFragment;
  };

  getEvent(nameOrSignatureOrTopic: 'Initialized'): EventFragment;
  getEvent(nameOrSignatureOrTopic: 'OwnershipTransferStarted'): EventFragment;
  getEvent(nameOrSignatureOrTopic: 'OwnershipTransferred'): EventFragment;
  getEvent(nameOrSignatureOrTopic: 'StateUpdated'): EventFragment;
}

export interface InitializedEventObject {
  version: number;
}
export type InitializedEvent = TypedEvent<[number], InitializedEventObject>;

export type InitializedEventFilter = TypedEventFilter<InitializedEvent>;

export interface OwnershipTransferStartedEventObject {
  previousOwner: string;
  newOwner: string;
}
export type OwnershipTransferStartedEvent = TypedEvent<
  [string, string],
  OwnershipTransferStartedEventObject
>;

export type OwnershipTransferStartedEventFilter =
  TypedEventFilter<OwnershipTransferStartedEvent>;

export interface OwnershipTransferredEventObject {
  previousOwner: string;
  newOwner: string;
}
export type OwnershipTransferredEvent = TypedEvent<
  [string, string],
  OwnershipTransferredEventObject
>;

export type OwnershipTransferredEventFilter =
  TypedEventFilter<OwnershipTransferredEvent>;

export interface StateUpdatedEventObject {
  id: BigNumber;
  blockN: BigNumber;
  timestamp: BigNumber;
  state: BigNumber;
}
export type StateUpdatedEvent = TypedEvent<
  [BigNumber, BigNumber, BigNumber, BigNumber],
  StateUpdatedEventObject
>;

export type StateUpdatedEventFilter = TypedEventFilter<StateUpdatedEvent>;

export interface Abi extends BaseContract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  interface: AbiInterface;

  queryFilter<TEvent extends TypedEvent>(
    event: TypedEventFilter<TEvent>,
    fromBlockOrBlockhash?: string | number | undefined,
    toBlock?: string | number | undefined,
  ): Promise<Array<TEvent>>;

  listeners<TEvent extends TypedEvent>(
    eventFilter?: TypedEventFilter<TEvent>,
  ): Array<TypedListener<TEvent>>;
  listeners(eventName?: string): Array<Listener>;
  removeAllListeners<TEvent extends TypedEvent>(
    eventFilter: TypedEventFilter<TEvent>,
  ): this;
  removeAllListeners(eventName?: string): this;
  off: OnEvent<this>;
  on: OnEvent<this>;
  once: OnEvent<this>;
  removeListener: OnEvent<this>;

  functions: {
    VERSION(overrides?: CallOverrides): Promise<[string]>;

    acceptOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;

    getGISTProof(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistProofStructOutput]>;

    getGISTProofByBlock(
      id: PromiseOrValue<BigNumberish>,
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistProofStructOutput]>;

    getGISTProofByRoot(
      id: PromiseOrValue<BigNumberish>,
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistProofStructOutput]>;

    getGISTProofByTime(
      id: PromiseOrValue<BigNumberish>,
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistProofStructOutput]>;

    getGISTRoot(overrides?: CallOverrides): Promise<[BigNumber]>;

    getGISTRootHistory(
      start: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistRootInfoStructOutput[]]>;

    getGISTRootHistoryLength(overrides?: CallOverrides): Promise<[BigNumber]>;

    getGISTRootInfo(
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistRootInfoStructOutput]>;

    getGISTRootInfoByBlock(
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistRootInfoStructOutput]>;

    getGISTRootInfoByTime(
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.GistRootInfoStructOutput]>;

    getStateInfoById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.StateInfoStructOutput]>;

    getStateInfoByIdAndState(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.StateInfoStructOutput]>;

    getStateInfoHistoryById(
      id: PromiseOrValue<BigNumberish>,
      startIndex: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[IState.StateInfoStructOutput[]]>;

    getStateInfoHistoryLengthById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[BigNumber]>;

    getVerifier(overrides?: CallOverrides): Promise<[string]>;

    idExists(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[boolean]>;

    initialize(
      verifierContractAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;

    owner(overrides?: CallOverrides): Promise<[string]>;

    pendingOwner(overrides?: CallOverrides): Promise<[string]>;

    renounceOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;

    setVerifier(
      newVerifierAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;

    stateExists(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<[boolean]>;

    transferOwnership(
      newOwner: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;

    transitState(
      id: PromiseOrValue<BigNumberish>,
      oldState: PromiseOrValue<BigNumberish>,
      newState: PromiseOrValue<BigNumberish>,
      isOldStateGenesis: PromiseOrValue<boolean>,
      a: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      b: [
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      ],
      c: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<ContractTransaction>;
  };

  VERSION(overrides?: CallOverrides): Promise<string>;

  acceptOwnership(
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  getGISTProof(
    id: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistProofStructOutput>;

  getGISTProofByBlock(
    id: PromiseOrValue<BigNumberish>,
    blockNumber: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistProofStructOutput>;

  getGISTProofByRoot(
    id: PromiseOrValue<BigNumberish>,
    root: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistProofStructOutput>;

  getGISTProofByTime(
    id: PromiseOrValue<BigNumberish>,
    timestamp: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistProofStructOutput>;

  getGISTRoot(overrides?: CallOverrides): Promise<BigNumber>;

  getGISTRootHistory(
    start: PromiseOrValue<BigNumberish>,
    length: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistRootInfoStructOutput[]>;

  getGISTRootHistoryLength(overrides?: CallOverrides): Promise<BigNumber>;

  getGISTRootInfo(
    root: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistRootInfoStructOutput>;

  getGISTRootInfoByBlock(
    blockNumber: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistRootInfoStructOutput>;

  getGISTRootInfoByTime(
    timestamp: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.GistRootInfoStructOutput>;

  getStateInfoById(
    id: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.StateInfoStructOutput>;

  getStateInfoByIdAndState(
    id: PromiseOrValue<BigNumberish>,
    state: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.StateInfoStructOutput>;

  getStateInfoHistoryById(
    id: PromiseOrValue<BigNumberish>,
    startIndex: PromiseOrValue<BigNumberish>,
    length: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<IState.StateInfoStructOutput[]>;

  getStateInfoHistoryLengthById(
    id: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<BigNumber>;

  getVerifier(overrides?: CallOverrides): Promise<string>;

  idExists(
    id: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<boolean>;

  initialize(
    verifierContractAddr: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  owner(overrides?: CallOverrides): Promise<string>;

  pendingOwner(overrides?: CallOverrides): Promise<string>;

  renounceOwnership(
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  setVerifier(
    newVerifierAddr: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  stateExists(
    id: PromiseOrValue<BigNumberish>,
    state: PromiseOrValue<BigNumberish>,
    overrides?: CallOverrides,
  ): Promise<boolean>;

  transferOwnership(
    newOwner: PromiseOrValue<string>,
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  transitState(
    id: PromiseOrValue<BigNumberish>,
    oldState: PromiseOrValue<BigNumberish>,
    newState: PromiseOrValue<BigNumberish>,
    isOldStateGenesis: PromiseOrValue<boolean>,
    a: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
    b: [
      [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
    ],
    c: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
    overrides?: Overrides & { from?: PromiseOrValue<string> },
  ): Promise<ContractTransaction>;

  callStatic: {
    VERSION(overrides?: CallOverrides): Promise<string>;

    acceptOwnership(overrides?: CallOverrides): Promise<void>;

    getGISTProof(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistProofStructOutput>;

    getGISTProofByBlock(
      id: PromiseOrValue<BigNumberish>,
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistProofStructOutput>;

    getGISTProofByRoot(
      id: PromiseOrValue<BigNumberish>,
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistProofStructOutput>;

    getGISTProofByTime(
      id: PromiseOrValue<BigNumberish>,
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistProofStructOutput>;

    getGISTRoot(overrides?: CallOverrides): Promise<BigNumber>;

    getGISTRootHistory(
      start: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistRootInfoStructOutput[]>;

    getGISTRootHistoryLength(overrides?: CallOverrides): Promise<BigNumber>;

    getGISTRootInfo(
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistRootInfoStructOutput>;

    getGISTRootInfoByBlock(
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistRootInfoStructOutput>;

    getGISTRootInfoByTime(
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.GistRootInfoStructOutput>;

    getStateInfoById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.StateInfoStructOutput>;

    getStateInfoByIdAndState(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.StateInfoStructOutput>;

    getStateInfoHistoryById(
      id: PromiseOrValue<BigNumberish>,
      startIndex: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<IState.StateInfoStructOutput[]>;

    getStateInfoHistoryLengthById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getVerifier(overrides?: CallOverrides): Promise<string>;

    idExists(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<boolean>;

    initialize(
      verifierContractAddr: PromiseOrValue<string>,
      overrides?: CallOverrides,
    ): Promise<void>;

    owner(overrides?: CallOverrides): Promise<string>;

    pendingOwner(overrides?: CallOverrides): Promise<string>;

    renounceOwnership(overrides?: CallOverrides): Promise<void>;

    setVerifier(
      newVerifierAddr: PromiseOrValue<string>,
      overrides?: CallOverrides,
    ): Promise<void>;

    stateExists(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<boolean>;

    transferOwnership(
      newOwner: PromiseOrValue<string>,
      overrides?: CallOverrides,
    ): Promise<void>;

    transitState(
      id: PromiseOrValue<BigNumberish>,
      oldState: PromiseOrValue<BigNumberish>,
      newState: PromiseOrValue<BigNumberish>,
      isOldStateGenesis: PromiseOrValue<boolean>,
      a: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      b: [
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      ],
      c: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      overrides?: CallOverrides,
    ): Promise<void>;
  };

  filters: {
    'Initialized(uint8)'(version?: null): InitializedEventFilter;
    Initialized(version?: null): InitializedEventFilter;

    'OwnershipTransferStarted(address,address)'(
      previousOwner?: PromiseOrValue<string> | null,
      newOwner?: PromiseOrValue<string> | null,
    ): OwnershipTransferStartedEventFilter;
    OwnershipTransferStarted(
      previousOwner?: PromiseOrValue<string> | null,
      newOwner?: PromiseOrValue<string> | null,
    ): OwnershipTransferStartedEventFilter;

    'OwnershipTransferred(address,address)'(
      previousOwner?: PromiseOrValue<string> | null,
      newOwner?: PromiseOrValue<string> | null,
    ): OwnershipTransferredEventFilter;
    OwnershipTransferred(
      previousOwner?: PromiseOrValue<string> | null,
      newOwner?: PromiseOrValue<string> | null,
    ): OwnershipTransferredEventFilter;

    'StateUpdated(uint256,uint256,uint256,uint256)'(
      id?: null,
      blockN?: null,
      timestamp?: null,
      state?: null,
    ): StateUpdatedEventFilter;
    StateUpdated(
      id?: null,
      blockN?: null,
      timestamp?: null,
      state?: null,
    ): StateUpdatedEventFilter;
  };

  estimateGas: {
    VERSION(overrides?: CallOverrides): Promise<BigNumber>;

    acceptOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;

    getGISTProof(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTProofByBlock(
      id: PromiseOrValue<BigNumberish>,
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTProofByRoot(
      id: PromiseOrValue<BigNumberish>,
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTProofByTime(
      id: PromiseOrValue<BigNumberish>,
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTRoot(overrides?: CallOverrides): Promise<BigNumber>;

    getGISTRootHistory(
      start: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTRootHistoryLength(overrides?: CallOverrides): Promise<BigNumber>;

    getGISTRootInfo(
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTRootInfoByBlock(
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getGISTRootInfoByTime(
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getStateInfoById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getStateInfoByIdAndState(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getStateInfoHistoryById(
      id: PromiseOrValue<BigNumberish>,
      startIndex: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getStateInfoHistoryLengthById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    getVerifier(overrides?: CallOverrides): Promise<BigNumber>;

    idExists(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    initialize(
      verifierContractAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;

    owner(overrides?: CallOverrides): Promise<BigNumber>;

    pendingOwner(overrides?: CallOverrides): Promise<BigNumber>;

    renounceOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;

    setVerifier(
      newVerifierAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;

    stateExists(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<BigNumber>;

    transferOwnership(
      newOwner: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;

    transitState(
      id: PromiseOrValue<BigNumberish>,
      oldState: PromiseOrValue<BigNumberish>,
      newState: PromiseOrValue<BigNumberish>,
      isOldStateGenesis: PromiseOrValue<boolean>,
      a: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      b: [
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      ],
      c: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    VERSION(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    acceptOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;

    getGISTProof(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTProofByBlock(
      id: PromiseOrValue<BigNumberish>,
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTProofByRoot(
      id: PromiseOrValue<BigNumberish>,
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTProofByTime(
      id: PromiseOrValue<BigNumberish>,
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTRoot(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    getGISTRootHistory(
      start: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTRootHistoryLength(
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTRootInfo(
      root: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTRootInfoByBlock(
      blockNumber: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getGISTRootInfoByTime(
      timestamp: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getStateInfoById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getStateInfoByIdAndState(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getStateInfoHistoryById(
      id: PromiseOrValue<BigNumberish>,
      startIndex: PromiseOrValue<BigNumberish>,
      length: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getStateInfoHistoryLengthById(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    getVerifier(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    idExists(
      id: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    initialize(
      verifierContractAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;

    owner(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    pendingOwner(overrides?: CallOverrides): Promise<PopulatedTransaction>;

    renounceOwnership(
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;

    setVerifier(
      newVerifierAddr: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;

    stateExists(
      id: PromiseOrValue<BigNumberish>,
      state: PromiseOrValue<BigNumberish>,
      overrides?: CallOverrides,
    ): Promise<PopulatedTransaction>;

    transferOwnership(
      newOwner: PromiseOrValue<string>,
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;

    transitState(
      id: PromiseOrValue<BigNumberish>,
      oldState: PromiseOrValue<BigNumberish>,
      newState: PromiseOrValue<BigNumberish>,
      isOldStateGenesis: PromiseOrValue<boolean>,
      a: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      b: [
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
        [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      ],
      c: [PromiseOrValue<BigNumberish>, PromiseOrValue<BigNumberish>],
      overrides?: Overrides & { from?: PromiseOrValue<string> },
    ): Promise<PopulatedTransaction>;
  };
}
