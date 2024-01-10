// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import {IdRegistry} from "../../src/System2.sol";
import {DelegateRegistry} from "../../src/System2.sol";
import {ItemRegistry} from "../../src/System2.sol";
import {ChannelRegistry} from "../../src/System2.sol";
import {StringRenderer} from "../../src/renderer/StringRenderer.sol";
import {NftRenderer} from "../../src/renderer/NftRenderer.sol";

contract FullTestScript is Script {

    IdRegistry public idRegistry = IdRegistry(0x73c68a5Cc6d6586CA5Bd2F0c6f8eC8524f33557b);  
    DelegateRegistry public delegateRegistry = DelegateRegistry(0xDc4D28a3010ad7aAfFc24c377Ebb7Cb4d32A1Ae9);    
    ChannelRegistry public channelRegistry = ChannelRegistry(0x372d44903056fCdF643B75a660Fb0e8D79A7293F);
    ItemRegistry public itemRegistry = ItemRegistry(0x5226c4A81ed525bdc4AA97558fb596ddd9B34e0E);
    StringRenderer public stringRenderer = StringRenderer(0x1358b4111fbfD1929D3D47cfab2f00bF134e3918);
    NftRenderer public nftRenderer = NftRenderer(0xc71780165ecEF5ba96B71b01B2ecA1F107A0B8c4);  
    
    function setUp() public {}

    function run() public {
        bytes32 privateKeyBytes = vm.envBytes32("PRIVATE_KEY");
        uint256 deployerPrivateKey = uint256(privateKeyBytes);

        vm.startBroadcast(deployerPrivateKey);

        // register id
        // idRegistry.register(address(0));
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
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), bytes("ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354"));
        uint256[] memory channels = new uint256[](1);
        channels[0] = 1;        
        newItemInput[0].channels = channels;
        // new item
        itemRegistry.newItems(1, newItemInput);        
        //                 
        vm.stopBroadcast();
    }
}

// ======= DEPLOY SCRIPTS =====

// source .env
// forge script script/transactions/FullTest.s.sol:FullTestScript -vvvv --rpc-url $RPC_URL --broadcast  