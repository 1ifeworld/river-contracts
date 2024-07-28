// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";

import {RiverRegistry} from "../src/RiverRegistry.sol";

contract RiverRegistryScript is Script {

    RiverRegistry public riverRegistry;
    uint256 startingPrice = 0;
    address startingPayoutRecipient = 0xC1fA1105e2b9Ca12d04676f4841479f106f3095e;
    address public syndicateEoa = 0x10826C01a27B5E655853d2C54078935DDB374e32;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);    
        
        // deploy riverRegistry
        riverRegistry = new RiverRegistry(deployerWallet.addr, startingPayoutRecipient, startingPrice);  

        // set trusted callers
        address[] memory trustedCallersForRiverRegistry = new address[](2);
        trustedCallersForRiverRegistry[0] = deployerWallet.addr;
        trustedCallersForRiverRegistry[1] = syndicateEoa;        
        bool[] memory trues = new bool[](trustedCallersForRiverRegistry.length);
        for (uint256 i; i < trustedCallersForRiverRegistry.length; ++i) {
            trues[i] = true;
        }      
        riverRegistry.setTrusted(trustedCallersForRiverRegistry, trues);

        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/RiverRegistry.s.sol:RiverRegistryScript -vvvv --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --verify --verifier-url https://api-sepolia.basescan.org/api --etherscan-api-key $BASESCAN_API_KEY