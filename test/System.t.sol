// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";

import {IdRegistry, DelegateRegistry, ChannelRegistry, ItemRegistry} from "../src/System.sol";
import {StringRenderer} from "../src/renderer/StringRenderer.sol";
import {NftRenderer} from "../src/renderer/NftRenderer.sol";

contract SystemTest is Test {       

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////   

    //////////////////////////////////////////////////
    // PARAMETERS
    //////////////////////////////////////////////////   

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    ChannelRegistry public channelRegistry;
    ItemRegistry public itemRegistry;
    StringRenderer public stringRenderer;
    NftRenderer public nftRenderer;
    Account public relayer;
    Account public user;     
    
    string ipfsString = "ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354";
    bytes ipfsBytes = bytes("ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354");
    uint256 nftChain = 31938;
    address nftContract = address(0x666);
    address nftId = address(72);
    bool nftHasUd = true;

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////   

    // Set-up called before each test
    function setUp() public {
        idRegistry = new IdRegistry();  
        delegateRegistry = new DelegateRegistry();  
        itemRegistry = new ItemRegistry(address(idRegistry), address(delegateRegistry));  
        channelRegistry = new ChannelRegistry(address(idRegistry), address(delegateRegistry), address(itemRegistry));  
        stringRenderer = new StringRenderer();  
        nftRenderer = new NftRenderer();  
        relayer = makeAccount("relayer");
        user = makeAccount("user");
    }    

    //////////////////////////////////////////////////
    // ID REGISTRY
    //////////////////////////////////////////////////    

    function test_register() public { 
        vm.prank(user.addr);
        idRegistry.register(address(0));
        assertEq(idRegistry.idCount(), 1);
        assertEq(idRegistry.idOf(user.addr), 1);
        assertEq(idRegistry.custodyOf(1), user.addr);        
        assertEq(idRegistry.recoveryOf(1), address(0));
    }

    //////////////////////////////////////////////////
    // CHANNEL REGISTRY + ITEM REGISTRY
    //////////////////////////////////////////////////    

    function test_newChannel() public {
        vm.startPrank(user.addr);
        // register userId to user
        idRegistry.register(address(0));
        // prep data for new channel
        uint256[] memory participants = new uint256[](1);
        participants[0] = 1;
        ChannelRegistry.Roles[] memory roles = new ChannelRegistry.Roles[](1);
        roles[0] = ChannelRegistry.Roles.ADMIN;
        // create new channel
        channelRegistry.newChannel(
            1,
            participants,
            roles,
            ipfsString
        );
        // test channel creation
        assertEq(channelRegistry.channelCount(), 1);
        assertEq(channelRegistry.creatorForChannel(1), 1);
        assertEq(channelRegistry.uriForChannel(1), ipfsString);
        require(channelRegistry.getRoleForChannel(1, 1) == ChannelRegistry.Roles.ADMIN, "incorrect role");
    }

    function test_newItem() public {
        vm.startPrank(user.addr);
        // register userId to user
        idRegistry.register(address(0));
        // prep data for new channel
        uint256[] memory participants = new uint256[](1);
        participants[0] = 1;
        ChannelRegistry.Roles[] memory roles = new ChannelRegistry.Roles[](1);
        roles[0] = ChannelRegistry.Roles.ADMIN;
        // create new channel
        channelRegistry.newChannel(
            1,
            participants,
            roles,
            ipfsString
        );
        // prep data for new item
        ItemRegistry.NewItemInfo[] memory newItemInfo = new ItemRegistry.NewItemInfo[](1);
        newItemInfo[0].renderer = address(stringRenderer);
        newItemInfo[0].data = ipfsBytes;
        uint256[] memory channels = new uint256[](1);
        channels[0] = 1;        
        newItemInfo[0].channels = channels;
        // create item
        (uint256[] memory itemIds, address[] memory pointers) = itemRegistry.newItems(
            1,
            address(channelRegistry),
            newItemInfo
        );
        // test new item
        assertEq(itemRegistry.itemCount(), 1);
        assertEq(itemRegistry.dataForItem(1), pointers[0]);
        assertEq(itemRegistry.rendererForItem(1), address(stringRenderer));
        assertEq(itemRegistry.creatorForItem(1), 1);
        assertEq(itemRegistry.itemUri(1), ipfsString);
        assertEq(channelRegistry.channelForItem(1), 1);
        assertEq(channelRegistry.adderForItem(1), 1);
        assertEq(channelRegistry.adderForItem(1), 1);
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////  

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }                       
}
