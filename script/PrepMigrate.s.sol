// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";
import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {RiverRegistry} from "../src/RiverRegistry.sol";

contract PrepMigrateScript is Script {

    RiverRegistry public riverRegistry;
    address public riverMultiSigRecovery = address(0xC2DBd41efC723563CBD9285E638Aad894745703B);
    string fileContents;
    string json;
    bytes data;

    struct CustodySet {
        address[] wallets;
    }

    function setUp() public {
        riverRegistry = RiverRegistry(payable(0xE7A49E4398b10e9E27cE02894701b9Dd8cC5B0c7));
    }

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        vm.createWallet(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        json = vm.readFile("./migration/FULLWALLETS.json");
        data = vm.parseJson(json);

        // Decode data into custody set
        CustodySet memory custodySet = abi.decode(data, (CustodySet));         

        riverRegistry.trustedPrepMigrationBatch(custodySet.wallets, riverMultiSigRecovery);


        vm.stopBroadcast();
    }
}

// ======= SCRIPTS =====
// source .env
// forge script script/PrepMigrate.s.sol:PrepMigrateScript -vvvv --rpc-url $BASE_MAINNET_RPC_URL --broadcast