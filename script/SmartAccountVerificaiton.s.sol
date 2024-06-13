// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console2} from "forge-std/Script.sol";
import {SafeSingletonDeployer} from "safe-singleton-deployer-sol/src/SafeSingletonDeployer.sol";

import {CoinbaseSmartWallet, CoinbaseSmartWalletFactory} from "smart-wallet/src/CoinbaseSmartWalletFactory.sol";
import {Mock6492Verifier} from "../test/Mocks/Mock6492Verifier.sol";

contract DeployFactoryScript is Script {
    address constant EXPECTED_IMPLEMENTATION = 0x000100abaad02f1cfC8Bbe32bD5a564817339E72;
    address constant EXPECTED_FACTORY = 0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a;

    function run() public {
        vm.startBroadcast();
        console2.log("Deploying on chain ID", block.chainid);
        CoinbaseSmartWalletFactory factory = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
        Mock6492Verifier verifier = new Mock6492Verifier();
        console2.log("factory", address(factory));
        console2.log("implementation", factory.implementation());
        console2.log("veifier", address(verifier));
        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====
//
// forge script script/SmartAccountVerificaiton.s.sol --broadcast --verify --verifier-url https://api-sepolia.etherscan.io/api --fork-url sepolia --etherscan-api-key $ETHERSCAN_API_KEY --account defaultKey --sender 0x04655832bcb0a9a0be8c5ab71e4d311464c97af5 -vvvv

// verifying contracts

// forge verify-contract --etherscan-api-key $ETHERSCAN_API_KEY 0x3FE8FC47FeD9f93B4d4a484e81896c6A8F3E874e lib/smart-wallet/src/CoinbaseSmartWalletFactory.sol:CoinbaseSmartWalletFactory --verifier-url https://api-sepolia.etherscan.io/api --rpc-url sepolia --watch --constructor-args 0x0000000000000000000000007c5dad8851fd97d57452ff1927f3ff62df866544

// forge verify-contract --etherscan-api-key $ETHERSCAN_API_KEY 0x199f7922393F1AaA53757a2C1f23b328955FDFb2 test/Mocks/Mock6492Verifier.sol:Mock6492Verifier --verifier-url https://api-sepolia.etherscan.io/api --rpc-url sepolia --watch
