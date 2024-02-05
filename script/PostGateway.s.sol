// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {PostGateway} from "../src/PostGateway.sol";

contract PostGatewayScript is Script {

    PostGateway public postGateway;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);
        postGateway = new PostGateway();

        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/PostGateway.s.sol:PostGatewayScript -vvvv --rpc-url $NOVA_RPC_URL --broadcast --verify --verifier-url https://api-nova.arbiscan.io/api --etherscan-api-key $NOVA_EXPLORER_API_KEY
// forge script script/PostGateway.s.sol:PostGatewayScript -vvvv --broadcast --fork-url http://localhost:8545