import { ethers } from 'ethers';
import { toBufferLE } from 'bigint-buffer';

export async function verifyState(
  rpcUrl: string,
  contractAddress: string,
  id: bigint,
  state: any,
): Promise<{
  latest: boolean;
  state: any;
  transition_timestamp: number | string;
}> {
  const stateABI = [
    {
      inputs: [
        {
          internalType: 'address',
          name: '_verifierContractAddr',
          type: 'address',
        },
      ],
      stateMutability: 'nonpayable',
      type: 'constructor',
    },
    {
      anonymous: false,
      inputs: [
        {
          indexed: false,
          internalType: 'uint256',
          name: 'id',
          type: 'uint256',
        },
        {
          indexed: false,
          internalType: 'uint64',
          name: 'blockN',
          type: 'uint64',
        },
        {
          indexed: false,
          internalType: 'uint64',
          name: 'timestamp',
          type: 'uint64',
        },
        {
          indexed: false,
          internalType: 'uint256',
          name: 'state',
          type: 'uint256',
        },
      ],
      name: 'StateUpdated',
      type: 'event',
    },
    {
      inputs: [{ internalType: 'uint256', name: 'id', type: 'uint256' }],
      name: 'getState',
      outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
      stateMutability: 'view',
      type: 'function',
    },
    {
      inputs: [
        { internalType: 'uint256', name: 'id', type: 'uint256' },
        { internalType: 'uint64', name: 'blockN', type: 'uint64' },
      ],
      name: 'getStateDataByBlock',
      outputs: [
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint256', name: '', type: 'uint256' },
      ],
      stateMutability: 'view',
      type: 'function',
    },
    {
      inputs: [{ internalType: 'uint256', name: 'id', type: 'uint256' }],
      name: 'getStateDataById',
      outputs: [
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint256', name: '', type: 'uint256' },
      ],
      stateMutability: 'view',
      type: 'function',
    },
    {
      inputs: [
        { internalType: 'uint256', name: 'id', type: 'uint256' },
        { internalType: 'uint64', name: 'timestamp', type: 'uint64' },
      ],
      name: 'getStateDataByTime',
      outputs: [
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint256', name: '', type: 'uint256' },
      ],
      stateMutability: 'view',
      type: 'function',
    },
    {
      inputs: [{ internalType: 'uint256', name: 'state', type: 'uint256' }],
      name: 'getTransitionInfo',
      outputs: [
        { internalType: 'uint256', name: '', type: 'uint256' },
        { internalType: 'uint256', name: '', type: 'uint256' },
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint64', name: '', type: 'uint64' },
        { internalType: 'uint256', name: '', type: 'uint256' },
        { internalType: 'uint256', name: '', type: 'uint256' },
      ],
      stateMutability: 'view',
      type: 'function',
    },
    {
      inputs: [
        { internalType: 'uint256', name: 'newState', type: 'uint256' },
        { internalType: 'uint256', name: 'genesisState', type: 'uint256' },
        { internalType: 'uint256', name: 'id', type: 'uint256' },
        { internalType: 'uint256[2]', name: 'a', type: 'uint256[2]' },
        { internalType: 'uint256[2][2]', name: 'b', type: 'uint256[2][2]' },
        { internalType: 'uint256[2]', name: 'c', type: 'uint256[2]' },
      ],
      name: 'initState',
      outputs: [],
      stateMutability: 'nonpayable',
      type: 'function',
    },
    {
      inputs: [
        { internalType: 'uint256', name: 'newState', type: 'uint256' },
        { internalType: 'uint256', name: 'id', type: 'uint256' },
        { internalType: 'uint256[2]', name: 'a', type: 'uint256[2]' },
        { internalType: 'uint256[2][2]', name: 'b', type: 'uint256[2][2]' },
        { internalType: 'uint256[2]', name: 'c', type: 'uint256[2]' },
      ],
      name: 'setState',
      outputs: [],
      stateMutability: 'nonpayable',
      type: 'function',
    },
  ];
  const ethersProvider = new ethers.providers.JsonRpcProvider(rpcUrl);
  const contract = new ethers.Contract(
    contractAddress,
    stateABI,
    ethersProvider,
  );
  const contractState = await contract.getState(id);

  if (contractState.toBigInt() === 0n) {
    const error = checkGenesisStateId(id, state);
    if (error) {
      throw new Error(error);
    }

    return { latest: true, state, transition_timestamp: 0 };
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
      transition_timestamp: transitionInfo[0].toBigInt(),
    };
  }

  return { latest: true, state, transition_timestamp: 0 };
}

export function checkGenesisStateId(id: bigint, state: string): string {
  const idBytes = toBufferLE(id, 31);
  const stateInt = BigInt(state);

  const typeBJP0 = Buffer.alloc(2);
  const stateBytes = toBufferLE(stateInt, 32);
  const idGenesisBytes = stateBytes.slice(-27); // we take last 27 bytes, because of swapped endianness
  const idFromStateBytes = Buffer.concat([
    typeBJP0,
    idGenesisBytes,
    calculateChecksum(typeBJP0, idGenesisBytes),
  ]);

  if (!idBytes.equals(idFromStateBytes)) {
    return `ID from genesis state (${JSON.stringify(
      idFromStateBytes.toJSON().data,
    )}) and provided (${JSON.stringify(idBytes.toJSON().data)}) don't match`;
  }

  return null;
}

export function calculateChecksum(type: Buffer, genesis: Buffer): Buffer {
  const checksumBytes = Buffer.concat([type, genesis]);

  let sum = 0;
  for (const val of checksumBytes.values()) {
    sum += val;
  }

  const checksum = Buffer.alloc(2);
  checksum[0] = sum >> 8;
  checksum[1] = sum & 0xff;

  return checksum;
}
