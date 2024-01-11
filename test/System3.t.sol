// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";

import {IdRegistry} from "../src/IdRegistry.sol";
import {DelegateRegistry} from "../src/DelegateRegistry.sol";
import {ChannelRegistry} from "../src/ChannelRegistry.sol";
import {ItemRegistry} from "../src/ItemRegistry.sol";

import {RoleBasedAccess} from "../src/logic/RoleBasedAccess.sol";
import {StringRenderer} from "../src/renderer/StringRenderer.sol";
import {NftRenderer} from "../src/renderer/NftRenderer.sol";

contract System3Test is Test {       

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
    RoleBasedAccess public roleBasedAccess;
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
        channelRegistry = new ChannelRegistry(address(idRegistry), address(delegateRegistry));  
        itemRegistry = new ItemRegistry(address(idRegistry), address(delegateRegistry), address(channelRegistry));  
        roleBasedAccess = new RoleBasedAccess(address(idRegistry), address(delegateRegistry));  
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
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = 1;
        RoleBasedAccess.Roles[] memory roles = new RoleBasedAccess.Roles[](1);
        roles[0] = RoleBasedAccess.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        channelRegistry.newChannel(
            1,
            ipfsString,
            address(roleBasedAccess),
            logicInit
        );
        // // test channel creation
        assertEq(channelRegistry.channelCount(), 1);
        assertEq(channelRegistry.logicForChannel(1), address(roleBasedAccess));
        assertEq(channelRegistry.uriForChannel(1), ipfsString);
        require(roleBasedAccess.rolesForChannel(address(channelRegistry), 1, 1) == RoleBasedAccess.Roles.ADMIN, "incorrect role");
    }

    function test_newItem() public {
        vm.startPrank(user.addr);
        // register userId to user
        idRegistry.register(address(0));
        // prep data for new channel
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = 1;
        RoleBasedAccess.Roles[] memory roles = new RoleBasedAccess.Roles[](1);
        roles[0] = RoleBasedAccess.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        channelRegistry.newChannel(
            1,
            ipfsString,
            address(roleBasedAccess),
            logicInit
        );
        // prep data for new item
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), ipfsBytes);
        uint256[] memory channels = new uint256[](1);
        channels[0] = 1;        
        newItemInput[0].channels = channels;
        // create item
        (, address[] memory pointers) = itemRegistry.newItems(1, newItemInput);
        // test new item
        assertEq(itemRegistry.itemCount(), 1);
        assertEq(itemRegistry.dataForItem(1), pointers[0]);
        assertEq(itemRegistry.adminForItem(1, 1), true);        
        assertEq(itemRegistry.addedItemToChannel(1, 1), 1); // itemid1 was added to channelid1 by userid1
        assertEq(itemRegistry.itemUri(1), ipfsString);
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////  

    function _sign(uint256 privateKey, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }                       
}
