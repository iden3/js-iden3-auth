/* eslint-disable max-len */

import { ethers } from 'ethers';
import { toBufferLE } from 'bigint-buffer';

/**
 * Verify identity state
 * @param rpcURL url to connect to the blockchain
 * @param contractAddress is an address of state contract
 * @param id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
 * @param state is bigint string representation of identity state
 */
export async function verifyState(rpcURL, contractAddress, id, state) {
    const stateABI = [{ 'inputs': [{ 'internalType': 'address', 'name': '_verifierContractAddr', 'type': 'address' }], 'stateMutability': 'nonpayable', 'type': 'constructor' }, { 'anonymous': false, 'inputs': [{ 'indexed': false, 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }, { 'indexed': false, 'internalType': 'uint64', 'name': 'blockN', 'type': 'uint64' }, { 'indexed': false, 'internalType': 'uint64', 'name': 'timestamp', 'type': 'uint64' }, { 'indexed': false, 'internalType': 'uint256', 'name': 'state', 'type': 'uint256' }], 'name': 'StateUpdated', 'type': 'event' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }], 'name': 'getState', 'outputs': [{ 'internalType': 'uint256', 'name': '', 'type': 'uint256' }], 'stateMutability': 'view', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }, { 'internalType': 'uint64', 'name': 'blockN', 'type': 'uint64' }], 'name': 'getStateDataByBlock', 'outputs': [{ 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }], 'stateMutability': 'view', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }], 'name': 'getStateDataById', 'outputs': [{ 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }], 'stateMutability': 'view', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }, { 'internalType': 'uint64', 'name': 'timestamp', 'type': 'uint64' }], 'name': 'getStateDataByTime', 'outputs': [{ 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }], 'stateMutability': 'view', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'state', 'type': 'uint256' }], 'name': 'getTransitionInfo', 'outputs': [{ 'internalType': 'uint256', 'name': '', 'type': 'uint256' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }, { 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint64', 'name': '', 'type': 'uint64' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }, { 'internalType': 'uint256', 'name': '', 'type': 'uint256' }], 'stateMutability': 'view', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'newState', 'type': 'uint256' }, { 'internalType': 'uint256', 'name': 'genesisState', 'type': 'uint256' }, { 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }, { 'internalType': 'uint256[2]', 'name': 'a', 'type': 'uint256[2]' }, { 'internalType': 'uint256[2][2]', 'name': 'b', 'type': 'uint256[2][2]' }, { 'internalType': 'uint256[2]', 'name': 'c', 'type': 'uint256[2]' }], 'name': 'initState', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function' }, { 'inputs': [{ 'internalType': 'uint256', 'name': 'newState', 'type': 'uint256' }, { 'internalType': 'uint256', 'name': 'id', 'type': 'uint256' }, { 'internalType': 'uint256[2]', 'name': 'a', 'type': 'uint256[2]' }, { 'internalType': 'uint256[2][2]', 'name': 'b', 'type': 'uint256[2][2]' }, { 'internalType': 'uint256[2]', 'name': 'c', 'type': 'uint256[2]' }], 'name': 'setState', 'outputs': [], 'stateMutability': 'nonpayable', 'type': 'function' }];
    const ethersProvider = new ethers.providers.JsonRpcProvider(rpcURL);
    const contract = new ethers.Contract(contractAddress, stateABI, ethersProvider);
    const contractState = await contract.getState(id);

    if (contractState.toBigInt() === 0n) {
        const error = checkGenesisStateId(id, state);
        if (error) {
            return { Error: error };
        }

        return { latest: true, state };
    }

    if (contractState.toBigInt() !== state) {
        // The non-empty state is returned, and it’s not equal to the state that the user has provided.
        // Get the time of the latest state and compare it to the transition time of state provided by the user.
        // The verification party can make a decision if it can accept this state based on that time frame
        // type TransitionInfo struct {
        //     ReplacedAtTimestamp *big.Int
        //     CreatedAtTimestamp *big.Int
        //     ReplacedAtBlock uint64
        //     CreatedAtBlock uint64
        //     ReplacedBy *big.Int
        //     ID *big.Int
        // }
        const transitionInfo = await contract.getTransitionInfo(contractState);

        if (transitionInfo[5].toBigInt() === 0n) {
            return { Error: 'Transition info contains invalid id' };
        }

        if (transitionInfo[0].toBigInt() === 0n) {
            return { Error: 'No information of transition for non-latest state' };
        }

        return { latest: false, state: state, transitionTimestamp: transitionInfo[0].toBigInt() };
    }

    // The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
    return { latest: true, state };
}

export function checkGenesisStateId(id, state) {
    const idBytes = toBufferLE(id, 31);
    const stateId = BigInt(state);

    // TypeBJP0 specifies the BJ-P0
    // - first 2 bytes: `00000000 00000000`
    // - curve of k_op: babyjubjub
    // - hash function: `Poseidon` with 4+4 elements
    const typeBJP0 = Buffer.alloc(2);
    const stateBytes = toBufferLE(stateId, 32);
    const idGenesisBytes = stateBytes.slice(-27); // we take last 27 bytes, because of swapped endianness
    const idFromStateBytes = Buffer.concat([
        typeBJP0,
        idGenesisBytes,
        calculateChecksum(typeBJP0, idGenesisBytes),
    ]);

    if (!idBytes.equals(idFromStateBytes)) {
        return `ID from genesis state (${JSON.stringify(idFromStateBytes.toJSON().data)}) and provided (${JSON.stringify(idBytes.toJSON().data)}) don't match`;
    }

    return null;
}

export function calculateChecksum(type, genesis) {
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
