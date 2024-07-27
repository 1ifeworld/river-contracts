// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {JSONParserLib} from "@solady/utils/JSONParserLib.sol";
import "forge-std/Script.sol";
import {console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {RiverRegistry} from "../src/RiverRegistry.sol";

contract FileScript is Script {

    RiverRegistry public riverRegistry;
    address public mockRecoveryAddress = address(0x11111111);
    string fileContents;
    string json;
    bytes data;
    struct CustodySet {
        address[] wallets;
    }

    function setUp() public {
        riverRegistry = RiverRegistry(payable(0x291a34a9F686D4f509FC77E3756d66B206E002f8));
    }

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);
        vm.startBroadcast(deployerPrivateKey);

        json = vm.readFile("./migration/240726_Custody.JSON");
        data = vm.parseJson(json);

        // Decode data into custody set
        CustodySet memory custodySet = abi.decode(data, (CustodySet));

        // first 50
        address[] memory first50 = new address[](50);
        for (uint256 i; i < 50; ++i) {
            first50[i] = custodySet.wallets[i];
        }
        // second 50
        address[] memory second50 = new address[](50);
        for (uint256 i; i < 50; ++i) {
            second50[i] = custodySet.wallets[i + 50];
        }        
        // third 50
        address[] memory third50 = new address[](50);
        for (uint256 i; i < 50; ++i) {
            third50[i] = custodySet.wallets[i + 100];
        }                

        riverRegistry.trustedPrepMigrationBatch(custodySet.wallets, mockRecoveryAddress);
        // riverRegistry.trustedPrepMigrationBatch(first50, mockRecoveryAddress);
        // riverRegistry.trustedPrepMigrationBatch(second50, mockRecoveryAddress);
        // riverRegistry.trustedPrepMigrationBatch(third50, mockRecoveryAddress);

        vm.stopBroadcast();
    }
}
// ======= SCRIPTS =====
// source .env
// forge script script/File.s.sol:FileScript -vvvv --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast

/*
  Txn analysis, prepMigrateBatch 50 wallets
    - Estimated gas price: 13.601518797 gwei
    - Estimated total gas used for script: 4884712
    - Estimated amount required: 0.066439502085931464 ETH 
    - Success hash: 0x1615d50837855cc7022712667480f055d798446454ece5bdda0ef343f92012de
    - Paid: 0.02525423452717868 ETH (3536444 gas * 7.14113797 gwei)
*/