// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console2} from "lib/forge-std/src/Script.sol";
import {Signature} from "../src/Signature.sol";

contract SignatureScript is Script {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    function run() public returns (Signature) {
        vm.startBroadcast();
        Signature sig = new Signature();
        vm.stopBroadcast();
        return sig;
    }
}
