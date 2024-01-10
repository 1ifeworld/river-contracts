// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.13;

// import "forge-std/Script.sol";

// import {IdRegistry} from "../src/System.sol";
// import {DelegateRegistry} from "../src/System.sol";
// import {ItemRegistry} from "../src/System.sol";
// import {ChannelRegistry} from "../src/System.sol";
// import {StringRenderer} from "../src/renderer/StringRenderer.sol";
// import {NftRenderer} from "../src/renderer/NftRenderer.sol";

// contract SystemSetupScript is Script {

//     IdRegistry public idRegistry;
//     DelegateRegistry public delegateRegistry;
//     ChannelRegistry public channelRegistry;
//     ItemRegistry public itemRegistry;
//     StringRenderer public stringRenderer;
//     NftRenderer public nftRenderer;
    
//     function setUp() public {}

//     function run() public {
//         bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
//         uint256 deployerPrivateKey = uint256(privateKeyBytes);

//         vm.startBroadcast(deployerPrivateKey);
        
//         idRegistry = new IdRegistry();  
//         delegateRegistry = new DelegateRegistry();  
//         itemRegistry = new ItemRegistry(address(idRegistry), address(delegateRegistry));  
//         channelRegistry = new ChannelRegistry(address(idRegistry), address(delegateRegistry), address(itemRegistry));  
//         stringRenderer = new StringRenderer();  
//         nftRenderer = new NftRenderer();      

//         vm.stopBroadcast();
//     }
// }

// // ======= DEPLOY SCRIPTS =====

// // source .env

// // forge script script/System.s.sol:SystemSetupScript -vvvv --broadcast --fork-url http://localhost:8545
// // forge script script/System.s.sol:SystemSetupScript -vvvv --rpc-url $RPC_URL --broadcast --verify --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?
// // forge script script/System.s.sol:SystemSetupScript -vvvv --rpc-url $RPC_URL --broadcast  
                                                           
// // forge verify-contract 0x8A8AfFE89d0E23b9C44e0078Fe525A7aDa3a1365 src/renderer/NftRenderer.sol:NftRenderer --verifier blockscout --verifier-url https://explorerl2new-river-j5bpjduqfv.t.conduit.xyz/api\?