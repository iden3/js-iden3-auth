export const stateABI = [
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
