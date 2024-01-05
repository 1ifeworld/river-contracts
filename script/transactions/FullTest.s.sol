// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {IdRegistry} from "../../src/System.sol";
import {DelegateRegistry} from "../../src/System.sol";
import {ItemRegistry} from "../../src/System.sol";
import {ChannelRegistry} from "../../src/System.sol";
import {StringRenderer} from "../../src/renderer/StringRenderer.sol";
import {NftRenderer} from "../../src/renderer/NftRenderer.sol";

contract FullTestScript is Script {

    IdRegistry public idRegistry = IdRegistry(0x73c68a5Cc6d6586CA5Bd2F0c6f8eC8524f33557b);  
    DelegateRegistry public delegateRegistry = DelegateRegistry(0xDc4D28a3010ad7aAfFc24c377Ebb7Cb4d32A1Ae9);
    ItemRegistry public itemRegistry = ItemRegistry(0xeC3D44B91Ca1720671Ca5405c4b25c82F18F1a66);
    ChannelRegistry public channelRegistry = ChannelRegistry(0x201957E490Ea29B4f42A68a21228D181867d6E39);    
    StringRenderer public stringRenderer = StringRenderer(0xf6B63Eb54EF06808495Dbb4D7EbFed675fFbCD72);
    NftRenderer public nftRenderer = NftRenderer(0x8A8AfFE89d0E23b9C44e0078Fe525A7aDa3a1365);
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);

        vm.startBroadcast(deployerPrivateKey);

        // register id
        idRegistry.register(address(0));
        // prep data for new channel
        uint256[] memory participants = new uint256[](1);
        participants[0] = 1;
        ChannelRegistry.Roles[] memory roles = new ChannelRegistry.Roles[](1);
        roles[0] = ChannelRegistry.Roles.ADMIN;
        // new channel
        channelRegistry.newChannel(
            1,
            participants,
            roles,
            "ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354"
        );
        // prep data for new item
        ItemRegistry.NewItemInfo[] memory newItemInfo = new ItemRegistry.NewItemInfo[](1);
        newItemInfo[0].renderer = address(stringRenderer);
        newItemInfo[0].data = bytes("ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354");
        uint256[] memory channels = new uint256[](1);
        channels[0] = 1;        
        newItemInfo[0].channels = channels;
        // new item
        itemRegistry.newItems(
            1,
            address(channelRegistry),
            newItemInfo
        );                        

        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====

// source .env
// forge script script/transactions/FullTest.s.sol:FullTestScript -vvvv --rpc-url $RPC_URL --broadcast  