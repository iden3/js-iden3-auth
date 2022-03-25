import 'snarkjs';
import 'web3-eth-contract';

async function calculateProof(message, publicSignals, proof) {

    // Verification of circuits public signals
    const metadata = extractMetadata(message);
    let token     = {
        ID       : metadata.AuthData.UserIdentifier,
        Challenge: metadata.AuthData.AuthenticationChallenge,
        State    : metadata.AuthData.UserState,
    };
    let stateInfo = verifyState(ethURL, contractAddress, token);
    console.log(stateInfo);

    // groth16 verify
    const vkey = await fetch('test/verification_key.json').then(function (res) {
        return res.json();
    });
    const res  = await snarkjs.groth16.verify(vkey, publicSignals, proof);

    console.log(res);
}

function extractMetadata() {
    // TBD
}

/**
 * Verify identity state
 * @param rpcURL url to connect to the blockchain
 * @param contractAddress is an address of state contract
 * @param id is base58 identifier  e.g. id:11A2HgCZ1pUcY8HoNDMjNWEBQXZdUnL3YVnVCUvR5s
 * @param state is bigint string representation of identity state
 */
function verifyState(rpcURL, contractAddress, id, state) {

    // get latest state for id from contract
    let stateContract = contractCall(contractAddress);
    if (err) {
        return err;
    }
    if (parseInt(stateContract) == 0) {
        let err = checkGenesisStateID(id, state);
        if (err) {
            return err;
        }
        return {Latest: true, State: state};
    }
    if (stateContract != state) {

        // The non-empty state is returned, and it’s not equal to the state that the user has provided.
        // Get the time of the latest state and compare it to the transition time of state provided by the user.
        // The verification party can make a decision if it can accept this state based on that time frame

        const timestamp = contractCall(contractAddress)
        if (!timestamp) {
            return 'no information of transition for non-latest state';
        }

        return {Latest: false, State: state, TransitionTimestamp: timestamp};
    }

    // The non-empty state is returned and equals to the state in provided proof which means that the user state is fresh enough, so we work with the latest user state.
    return {Latest: true, State: state.String()};
}

function contractCall(contractAddress) {

    const ethclient = new web3.eth.Contract({
        provider: rpcURL
    }, contractAddress);
    ethclient.send({}).on('receipt', function (outputs) {
        if (!outputs[0]) {
            return 'no state output';
        } else {
            return outputs[0];
        }
    });

}
