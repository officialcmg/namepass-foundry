// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {NamepassBasename} from "../src/NamepassBasename.sol";

contract NamepassBasenameScript is Script {
    NamepassBasename public namepassBasename;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Deploy with a mock controller address - replace with actual controller
        address mockController = address(0x1234567890123456789012345678901234567890);
        namepassBasename = new NamepassBasename(mockController);

        vm.stopBroadcast();
    }
}
