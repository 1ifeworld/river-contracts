// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "forge-std/Script.sol";

import {IdRegistry} from "../src/IdRegistry.sol";

contract IdRegistryScript is Script {

    IdRegistry public idRegistry;    
    address public firstTrustedCaller = 0x07926020Ab18a3cCf4Bbff7ee886a0df8bCA0560;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);
        
        idRegistry = new IdRegistry(deployerWallet.addr);  
        idRegistry.setTrustedCaller(firstTrustedCaller);

        vm.stopBroadcast();
    }
}
// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/IdRegistry.s.sol:IdRegistryScript -vvvv --rpc-url $OPTIMISM_RPC_URL --broadcast --verify --verifier-url https://api-optimistic.etherscan.io/api --etherscan-api-key $OPTIMISM_EXPLORER_API_KEY
// forge script script/IdRegistry.s.sol:IdRegistryScript -vvvv --broadcast --fork-url http://localhost:8545