import 'snarkjs';
import { ethers } from 'ethers';

// переделать на ENV переменную infura
const ETHER_RPC_URL = 'https://ropsten.infura.io/v3/182bafeca1a4413e8608bf34fd3aa873';

// TestVerifyPublishedLatestState
// console.log(await verifyState(
//     ETHER_RPC_URL,
//     '0xE4F771f86B34BF7B323d9130c385117Ec39377c3',
//     259789390735913800425840589583206248151905278055521460389980943556380393472n,
//     14765322533580957814676911851067597009232239218105294460702004369607798613104n,
// ));

// TestVerifyStateTransitionCheck: latest state - not equal
// console.log(await verifyState(
//     ETHER_RPC_URL,
//     '0x456D5eD5dca5A4B46cDeF12ff0Fc9F0c60A29Afe',
//     367594446074802395435725357511631230269128032558677653124422983977269133312n,
//     15897377538691446922446254839699772977046010197592168446070901098705306666881n,
// ));

// TestVerifyGenesisState
console.log(await verifyState(
    ETHER_RPC_URL,
    '0xE4F771f86B34BF7B323d9130c385117Ec39377c3',
    371135506535866236563870411357090963344408827476607986362864968105378316288n,
    16751774198505232045539489584666775489135471631443877047826295522719290880931n,
));

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
            return {Error: 'Transition info contains invalid id'};
        }

        if (transitionInfo[0].toBigInt() === 0n) {
            return {Error: 'No information of transition for non-latest state'};
        }

        return {Latest: false, State: state, TransitionTimestamp: transitionInfo[0].toBigInt()};
    }

    // The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
    return {Latest: true, State: state};
}

function checkGenesisStateID(id, state) {
    let stateHash = longIntToByteArray(state.toString());
    stateHash = changeEndiannessHex(stateHash);
    const idFromState = core.IdGenesisFromIdenState(stateHash).String();

    if (idFromState !== id) {
        return "ID from genesis state (" + idFromState + ") and provided (" + id + ") don't match";
    }

    return null;
}

function longIntToByteArray(number) {

    // Represent the input as a 32-bytes array
    const byteArray = Array(32).fill(0);

    for (let index = 0; index < byteArray.length; index++) {
        const byte       = number & 0xff;
        byteArray[index] = byte;
        number           = (number - byte) / 256;
    }

    return byteArray;
};

function changeEndiannessHex(val) {
    return ((val & 0xFF) << 8)
        | ((val >> 8) & 0xFF);
}
