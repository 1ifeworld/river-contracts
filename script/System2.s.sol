// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {IdRegistry} from "../src/System2.sol";
import {DelegateRegistry} from "../src/System2.sol";
import {ItemRegistry} from "../src/System2.sol";
import {ChannelRegistry} from "../src/System2.sol";
import {StringRenderer} from "../src/renderer/StringRenderer.sol";
import {NftRenderer} from "../src/renderer/NftRenderer.sol";

contract System2SetupScript is Script {

    IdRegistry public idRegistry = IdRegistry(0x73c68a5Cc6d6586CA5Bd2F0c6f8eC8524f33557b);
    DelegateRegistry public delegateRegistry = DelegateRegistry(0xDc4D28a3010ad7aAfFc24c377Ebb7Cb4d32A1Ae9);
    ChannelRegistry public channelRegistry;
    ItemRegistry public itemRegistry;
    StringRenderer public stringRenderer;
    NftRenderer public nftRenderer;
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);

        vm.startBroadcast(deployerPrivateKey);
        
        // idRegistry = new IdRegistry();  
        // delegateRegistry = new DelegateRegistry();  
        channelRegistry = new ChannelRegistry(address(idRegistry), address(delegateRegistry));  
        itemRegistry = new ItemRegistry(address(idRegistry), address(delegateRegistry), address(channelRegistry));          
        // stringRenderer = new StringRenderer();  
        // nftRenderer = new NftRenderer();      

        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====

// source .env

// forge script script/System2.s.sol:System2SetupScript -vvvv --broadcast --fork-url http://localhost:8545
// forge script script/System2.s.sol:System2SetupScript -vvvv --rpc-url $RPC_URL --broadcast --verify --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?
// forge script script/System2.s.sol:System2SetupScript -vvvv --rpc-url $RPC_URL --broadcast  
                                                           
// forge verify-contract 0xc71780165ecEF5ba96B71b01B2ecA1F107A0B8c4 src/renderer/NftRenderer.sol:NftRenderer --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?
// forge verify-contract 0x1358b4111fbfD1929D3D47cfab2f00bF134e3918 src/renderer/StringRenderer.sol:StringRenderer --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?


// forge verify-contract 0x5226c4A81ed525bdc4AA97558fb596ddd9B34e0E src/System2.sol:ItemRegistry --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?
// forge verify-contract 0x372d44903056fCdF643B75a660Fb0e8D79A7293F src/System2.sol:ChannelRegistry --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?