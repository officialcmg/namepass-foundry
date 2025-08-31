// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {NamepassBasename} from "../src/NamepassBasename.sol";

contract NamepassBasenameScript is Script {
    NamepassBasename public namepassBasename;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Base Mainnet Basename Registrar Controller
        address baseMainnetController = address(0x4cCb0BB02FCABA27e82a56646E81d8c5bC4119a5);
        
        namepassBasename = new NamepassBasename(baseMainnetController);
        
        console.log("NamepassBasename deployed to:", address(namepassBasename));
        console.log("Controller address:", baseMainnetController);

        vm.stopBroadcast();
    }
}
