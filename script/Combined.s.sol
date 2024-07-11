// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "forge-std/Script.sol";

import {IdRegistry} from "../src/IdRegistry.sol";
import {KeyRegistry} from "../src/KeyRegistry.sol";
import {SignedKeyRequestValidator} from "../src/validators/SignedKeyRequestValidator.sol";
import {IMetadataValidator} from "../src/interfaces/IMetadataValidator.sol";

contract CombinedScript is Script {

    IdRegistry public idRegistry;    
    KeyRegistry public keyRegistry;    
    SignedKeyRequestValidator public validator;    
    address public firstTrustedCaller = 0x2167dcea5210A0744A4718Ea4C56c042a2f84269;
    address public secondTrustedCaller = 0x10826C01a27B5E655853d2C54078935DDB374e32;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);
        VmSafe.Wallet memory deployerWallet = vm.createWallet(deployerPrivateKey);

        vm.startBroadcast(deployerPrivateKey);

        // setup trusted caller variables
        address[] memory trustedCallers = new address[](2);
        trustedCallers[0] = firstTrustedCaller;
        trustedCallers[1] = secondTrustedCaller;
        bool[] memory statuses = new bool[](2);
        statuses[0] = true;
        statuses[1] = true;
        
        
        idRegistry = new IdRegistry(deployerWallet.addr);  
        idRegistry.setTrustedCallers(trustedCallers, statuses);
        validator = new SignedKeyRequestValidator(address(idRegistry), deployerWallet.addr);
        keyRegistry = new KeyRegistry(address(idRegistry), deployerWallet.addr, 500);
        keyRegistry.setTrustedCallers(trustedCallers, statuses);
        keyRegistry.setValidator(1, 1, IMetadataValidator(validator));

        vm.stopBroadcast();
    }
}
// ======= DEPLOY SCRIPTS =====
// source .env
// forge script script/Combined.s.sol:CombinedScript -vvvv --rpc-url $BASE_SEPOLIA_RPC_URL --broadcast --verify --verifier-url https://api-sepolia.basescan.org/api --etherscan-api-key $BASESCAN_API_KEY
// forge script script/IdRegistry.s.sol:IdRegistryScript -vvvv --broadcast --fork-url http://localhost:8545