import 'snarkjs';
import { ethers } from 'ethers';

// переделать на ENV переменную infura
const ETHER_RPC_URL = 'https://ropsten.infura.io/v3/182bafeca1a4413e8608bf34fd3aa873';

verifyState(
    ETHER_RPC_URL,
    '0xE4F771f86B34BF7B323d9130c385117Ec39377c3',
    '0x0000357c5daf75f44de1594e001389b9fae265773192a77a73203bdc0c0ca2',
    ''
);

async function verifyProof(message, contractAddress, publicSignals, proof) {

    // Verification of circuits public signals
    const token = extractMetadata(message);
    let stateInfo = verifyState(ETHER_RPC_URL, contractAddress, token.ID, token.State);
    console.log(stateInfo);

    // groth16 verify
    const vkey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });
    const res  = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    console.log(res);

}

function extractMetadata(message) {
    const metadata = JSON.parse(message)
    return {
        ID       : metadata.AuthData.UserIdentifier,
        Challenge: metadata.AuthData.AuthenticationChallenge,
        State    : metadata.AuthData.UserState,
    };
}

/**
 * Verify identity state
 * @param rpcURL url to connect to the blockchain
 * @param contractAddress is an address of state contract
 * @param id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
 * @param state is bigint string representation of identity state
 */
async function verifyState(rpcURL, contractAddress, id, state) {

    const stateABI       = [{"inputs":[{"internalType":"address","name":"_verifierContractAddr","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"id","type":"uint256"},{"indexed":false,"internalType":"uint64","name":"blockN","type":"uint64"},{"indexed":false,"internalType":"uint64","name":"timestamp","type":"uint64"},{"indexed":false,"internalType":"uint256","name":"state","type":"uint256"}],"name":"StateUpdated","type":"event"},{"inputs":[{"internalType":"uint256","name":"id","type":"uint256"}],"name":"getState","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"id","type":"uint256"},{"internalType":"uint64","name":"blockN","type":"uint64"}],"name":"getStateDataByBlock","outputs":[{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"id","type":"uint256"}],"name":"getStateDataById","outputs":[{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"id","type":"uint256"},{"internalType":"uint64","name":"timestamp","type":"uint64"}],"name":"getStateDataByTime","outputs":[{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"state","type":"uint256"}],"name":"getTransitionInfo","outputs":[{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint64","name":"","type":"uint64"},{"internalType":"uint256","name":"","type":"uint256"},{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"newState","type":"uint256"},{"internalType":"uint256","name":"genesisState","type":"uint256"},{"internalType":"uint256","name":"id","type":"uint256"},{"internalType":"uint256[2]","name":"a","type":"uint256[2]"},{"internalType":"uint256[2][2]","name":"b","type":"uint256[2][2]"},{"internalType":"uint256[2]","name":"c","type":"uint256[2]"}],"name":"initState","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"newState","type":"uint256"},{"internalType":"uint256","name":"id","type":"uint256"},{"internalType":"uint256[2]","name":"a","type":"uint256[2]"},{"internalType":"uint256[2][2]","name":"b","type":"uint256[2][2]"},{"internalType":"uint256[2]","name":"c","type":"uint256[2]"}],"name":"setState","outputs":[],"stateMutability":"nonpayable","type":"function"}];
    const ethersProvider = new ethers.providers.JsonRpcProvider(rpcURL);
    const contract       = new ethers.Contract(contractAddress, stateABI, ethersProvider);
    const contractState  = await contract.getState(id);

    if (contractState.toNumber() === 0) {
        const error = checkGenesisStateID(id, state);
        if (error) {
            return {Error: error};
        }
        
        return {Latest: true, State: state};
    }

    if (contractState.toBigInt() != state) {

        // The non-empty state is returned, and it’s not equal to the state that the user has provided.
        // Get the time of the latest state and compare it to the transition time of state provided by the user.
        // The verification party can make a decision if it can accept this state based on that time frame
        const timestamp = contract.getTransitionTimestamp(id);
        if (!timestamp) {
            return {Error: 'No information of transition for non-latest state'};
        }

        return {Latest: false, State: state, TransitionTimestamp: timestamp};
    }

    // The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
    return {Latest: true, State: state};
}

function checkGenesisStateID(id, state) {

    const stateHash = merkletree.NewHashFromBigInt(state);
    const IDFromState = core.IdGenesisFromIdenState(stateHash).String();

    // const elemBytes = merkletree.NewElemBytesFromBigInt(id);
    // const IDFromParam = core.IDFromBytes(elemBytes[:31]);

    if (IDFromState !== id) {
        return "ID from genesis state (" + IDFromState + ") and provided (" + IDFromParam + ") don't match";
    }

    return null;
}
