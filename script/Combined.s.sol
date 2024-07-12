// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";

import {IdRegistry} from "../src/IdRegistry.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {Bundler} from "../src/Bundler.sol";
import {SignedKeyRequestValidator} from "../src/validators/SignedKeyRequestValidator.sol";
import {IMetadataValidator} from "../src/interfaces/IMetadataValidator.sol";

contract CombinedScript is Script {

    IdRegistry public idRegistry;    
    KeyRegistry public keyRegistry;    
    SignedKeyRequestValidator public validator;    
    Bundler public bundler;    
    address public syndicateEoa = 0x10826C01a27B5E655853d2C54078935DDB374e32;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);
        
        // deploy id validator
        idRegistry = new IdRegistry(deployerWallet.addr);  
        validator = new SignedKeyRequestValidator(address(idRegistry), deployerWallet.addr);
        keyRegistry = new KeyRegistry(address(idRegistry), deployerWallet.addr, 500);
        bundler = new Bundler(address(idRegistry), address(keyRegistry), deployerWallet.addr);

        address[] memory trustedCallersForBundler = new address[](2);
        address[] memory bundlerAsTrustedCaller = new address[](1);
        trustedCallersForBundler[0] = deployerWallet.addr;
        trustedCallersForBundler[1] = syndicateEoa;
        bundlerAsTrustedCaller[0] = address(bundler);
        bool[] memory statusesForBundler = new bool[](2);
        bool[] memory statusesForIdAndKey = new bool[](1);
        statusesForBundler[0] = true;
        statusesForBundler[1] = true;
        statusesForIdAndKey[0] = true;

        bundler.setTrustedCallers(trustedCallersForBundler, statusesForBundler);
        idRegistry.setTrustedCallers(bundlerAsTrustedCaller, statusesForIdAndKey);
        keyRegistry.setTrustedCallers(bundlerAsTrustedCaller, statusesForIdAndKey);

        vm.stopBroadcast();
    }
}
// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/Combined.s.sol:CombinedScript -vvvv --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --verify --verifier-url https://api-sepolia.basescan.org/api --etherscan-api-key $BASESCAN_API_KEY
// forge script script/IdRegistry.s.sol:IdRegistryScript -vvvv --broadcast --fork-url http://localhost:8545