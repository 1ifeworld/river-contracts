// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";

import {RiverRegistry} from "../src/RiverRegistry.sol";

contract RiverRegistryScript is Script {

    RiverRegistry public riverRegistry;
    uint256 startingPrice = 0;
    
    address public riverBaseMultisig = 0xC2DBd41efC723563CBD9285E638Aad894745703B;
    address public syndicateEoa = 0xEBB610288D38C8eA6B758950e3C89F35Ea073cf1;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);    
        
        // deploy riverRegistry
        riverRegistry = new RiverRegistry(deployerWallet.addr, riverBaseMultisig, startingPrice);  

        // set trusted callers
        address[] memory trustedCallersForRiverRegistry = new address[](3);
        trustedCallersForRiverRegistry[0] = deployerWallet.addr;
        trustedCallersForRiverRegistry[1] = riverBaseMultisig;
        trustedCallersForRiverRegistry[2] = syndicateEoa;        
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
// forge script script/RiverRegistry.s.sol:RiverRegistryScript -vvvv --rpc-url $BASE_MAINNET_RPC_URL --broadcast --verify --verifier-url https://api.basescan.org/api --etherscan-api-key $BASESCAN_API_KEY