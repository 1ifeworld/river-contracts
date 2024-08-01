// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";
import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {RiverRegistry} from "../src/RiverRegistry.sol";

contract PrepMigrateScript is Script {

    RiverRegistry public riverRegistry;
    address public mockRecoveryAddress = address(0x11111111);
    string fileContents;
    string json;
    bytes data;
    struct CustodySet {
        address[] wallets;
    }

    function setUp() public {
        // riverRegistry = RiverRegistry(payable(0x7B17A93373e2E862Fa5f4A78F4dc25C6210e990C));
        // riverRegistry = RiverRegistry(payable(0x111dec3610c4ceE5291e4aEF4DeAB6FE394a03Cd));
        riverRegistry = RiverRegistry(payable(0xAD74EfC3d72945eC82c8DaD7535E59670677f502));
    }

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        vm.createWallet(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        json = vm.readFile("./migration/240801_Custody.json");
        data = vm.parseJson(json);

        // Decode data into custody set
        CustodySet memory custodySet = abi.decode(data, (CustodySet));

        // // first 50
        // address[] memory first50 = new address[](50);
        // for (uint256 i; i < 50; ++i) {
        //     first50[i] = custodySet.wallets[i];
        // }             

        riverRegistry.trustedPrepMigrationBatch(custodySet.wallets, mockRecoveryAddress);


        vm.stopBroadcast();
    }
}

// ======= SCRIPTS =====
// source .env
// forge script script/PrepMigrate.s.sol:PrepMigrateScript -vvvv --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast