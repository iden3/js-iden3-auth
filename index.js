import 'snarkjs';
import { ethers } from 'ethers';

const ETHER_RPC_URL = 'https://ropsten.etherscan.io/address/0xE4F771f86B34BF7B323d9130c385117Ec39377c3';

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
function verifyState(rpcURL, contractAddress, id, state) {

    const ethersProvider = new ethers.providers.JsonRpcProvider(rpcURL);

    // The ERC-20 Contract ABI, which is a common contract interface
    // for tokens (this is the Human-Readable ABI format)
    const abi = [
        "function getState() view returns (string)",
        "function getTransitionTimestamp() view returns (int)",
    ];

    const contract = new ethers.Contract(contractAddress, abi, ethersProvider);
    const stateContract = contract.getState(id) + '';

    if (stateContract === '0') {
        const error = checkGenesisStateID(id, state);
        if (error) {
            return {Error: error};
        }
        return {Latest: true, State: state};
    }
    if (stateContract != state) {

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
