import 'snarkjs';
import { ethers } from 'ethers';

// переделать на ENV переменную infura
const ETHER_RPC_URL = 'https://ropsten.infura.io/v3/182bafeca1a4413e8608bf34fd3aa873';

// verifyState(
//     ETHER_RPC_URL,
//     '0xE4F771f86B34BF7B323d9130c385117Ec39377c3',
//     '0x0000357C5DAF75F44DE1594E001389B9FAE265773192A77A73203BDC0C0CA2', // base58 decoded of "113Rq7d5grTGzqF7phKCRjxpC597eMa2USzm9rmpoj"
//     '5816868615164565912277677884704888703982258184820398645933682814085602171910'
// );

verifyState(
    ETHER_RPC_URL,
    '0xE4F771f86B34BF7B323d9130c385117Ec39377c3',
    '0x93091c0f5cceeee677639242ca10116924bb0b0337035385aa275f02370000', // hex of 259789390735913800425840589583206248151905278055521460389980943556380393472
    '0x20a4e05b959c981ae21db9695bea64bf4e7d6008d9a77bf44fb71506325ce470' // hex of 14765322533580957814676911851067597009232239218105294460702004369607798613104
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

    if (contractState.toBigInt() === 0n) {
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

console.log(id);
console.log(state);
return null;

    const stateHash = merkletree.NewHashFromBigInt(state);
    const idFromState = core.IdGenesisFromIdenState(stateHash).String();

    if (idFromState !== id) {
        return "ID from genesis state (" + idFromState + ") and provided (" + id + ") don't match";
    }

    return null;
}
