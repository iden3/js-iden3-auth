/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Contract, Signer, utils } from "ethers";
import type { Provider } from "@ethersproject/providers";
import type { Abi, AbiInterface } from "../Abi";

const _abi = [
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint8",
        name: "version",
        type: "uint8",
      },
    ],
    name: "Initialized",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: true,
        internalType: "address",
        name: "previousOwner",
        type: "address",
      },
      {
        indexed: true,
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "OwnershipTransferred",
    type: "event",
  },
  {
    anonymous: false,
    inputs: [
      {
        indexed: false,
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "blockN",
        type: "uint256",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
      {
        indexed: false,
        internalType: "uint256",
        name: "state",
        type: "uint256",
      },
    ],
    name: "StateUpdated",
    type: "event",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
    ],
    name: "getGISTProof",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256[32]",
            name: "siblings",
            type: "uint256[32]",
          },
          {
            internalType: "uint256",
            name: "oldKey",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "oldValue",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "isOld0",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "key",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "value",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "fnc",
            type: "uint256",
          },
        ],
        internalType: "struct Proof",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "blockNumber",
        type: "uint256",
      },
    ],
    name: "getGISTProofByBlock",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256[32]",
            name: "siblings",
            type: "uint256[32]",
          },
          {
            internalType: "uint256",
            name: "oldKey",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "oldValue",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "isOld0",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "key",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "value",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "fnc",
            type: "uint256",
          },
        ],
        internalType: "struct Proof",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "root",
        type: "uint256",
      },
    ],
    name: "getGISTProofByRoot",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256[32]",
            name: "siblings",
            type: "uint256[32]",
          },
          {
            internalType: "uint256",
            name: "oldKey",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "oldValue",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "isOld0",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "key",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "value",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "fnc",
            type: "uint256",
          },
        ],
        internalType: "struct Proof",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
    ],
    name: "getGISTProofByTime",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256[32]",
            name: "siblings",
            type: "uint256[32]",
          },
          {
            internalType: "uint256",
            name: "oldKey",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "oldValue",
            type: "uint256",
          },
          {
            internalType: "bool",
            name: "isOld0",
            type: "bool",
          },
          {
            internalType: "uint256",
            name: "key",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "value",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "fnc",
            type: "uint256",
          },
        ],
        internalType: "struct Proof",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getGISTRoot",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "start",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "length",
        type: "uint256",
      },
    ],
    name: "getGISTRootHistory",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByRoot",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct RootInfo[]",
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getGISTRootHistoryLength",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "root",
        type: "uint256",
      },
    ],
    name: "getGISTRootInfo",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByRoot",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct RootInfo",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "blockNumber",
        type: "uint256",
      },
    ],
    name: "getGISTRootInfoByBlock",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByRoot",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct RootInfo",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
    ],
    name: "getGISTRootInfoByTime",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "root",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByRoot",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct RootInfo",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
    ],
    name: "getStateInfoById",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "id",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "state",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByState",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct StateInfo",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "state",
        type: "uint256",
      },
    ],
    name: "getStateInfoByState",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "id",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "state",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByState",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct StateInfo",
        name: "",
        type: "tuple",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "startIndex",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "length",
        type: "uint256",
      },
    ],
    name: "getStateInfoHistoryById",
    outputs: [
      {
        components: [
          {
            internalType: "uint256",
            name: "id",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "state",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedByState",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtTimestamp",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "createdAtBlock",
            type: "uint256",
          },
          {
            internalType: "uint256",
            name: "replacedAtBlock",
            type: "uint256",
          },
        ],
        internalType: "struct StateInfo[]",
        name: "",
        type: "tuple[]",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
    ],
    name: "getStateInfoHistoryLengthById",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "getVerifier",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "contract IVerifier",
        name: "verifierContractAddr",
        type: "address",
      },
    ],
    name: "initialize",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "owner",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [],
    name: "renounceOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newVerifierAddr",
        type: "address",
      },
    ],
    name: "setVerifier",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "stateEntries",
    outputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "timestamp",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "block",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "replacedBy",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    name: "statesHistories",
    outputs: [
      {
        internalType: "uint256",
        name: "",
        type: "uint256",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "address",
        name: "newOwner",
        type: "address",
      },
    ],
    name: "transferOwnership",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "uint256",
        name: "id",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "oldState",
        type: "uint256",
      },
      {
        internalType: "uint256",
        name: "newState",
        type: "uint256",
      },
      {
        internalType: "bool",
        name: "isOldStateGenesis",
        type: "bool",
      },
      {
        internalType: "uint256[2]",
        name: "a",
        type: "uint256[2]",
      },
      {
        internalType: "uint256[2][2]",
        name: "b",
        type: "uint256[2][2]",
      },
      {
        internalType: "uint256[2]",
        name: "c",
        type: "uint256[2]",
      },
    ],
    name: "transitState",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "verifier",
    outputs: [
      {
        internalType: "contract IVerifier",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
] as const;

export class Abi__factory {
  static readonly abi = _abi;
  static createInterface(): AbiInterface {
    return new utils.Interface(_abi) as AbiInterface;
  }
  static connect(address: string, signerOrProvider: Signer | Provider): Abi {
    return new Contract(address, _abi, signerOrProvider) as Abi;
  }
}
