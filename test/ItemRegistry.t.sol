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

contract ItemRegistryTest is Test {       

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////   

    string public ipfsString = "ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354";
    bytes public ipfsBytes = bytes("ipfs://bafybeiczsscdsbs7ffqz55asqdf3smv6klcw3gofszvwlyarci47bgf354");
    uint256 public nftChain = 31938;
    address public nftContract = address(0x666);
    address public nftId = address(72);
    bool public nftHasUd = true;    

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////   

    /* contracts + accounts */
    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    ChannelRegistry public channelRegistry;
    ItemRegistry public itemRegistry;
    StringRenderer public stringRenderer;
    RoleBasedAccess public roleBasedAccess;
    NftRenderer public nftRenderer;
    Account public relayer;
    Account public user;     
    Account public malicious;     
    /* values */
    uint256 public registeredUserId;
    bytes32 public channelHash;
    
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
        malicious = makeAccount("malicious");
        vm.startPrank(user.addr);        
        // register id to user
        registeredUserId = idRegistry.register(address(0));
        // // create channel for user
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = registeredUserId;
        RoleBasedAccess.Roles[] memory roles = new RoleBasedAccess.Roles[](1);
        roles[0] = RoleBasedAccess.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        channelHash = channelRegistry.newChannel(
            registeredUserId,
            ipfsString,
            address(roleBasedAccess),
            logicInit
        );        
        // end prank
        vm.stopPrank();
    }    

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////    

    function test_sigBased_newItem() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for new item
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), ipfsBytes);
        bytes32[] memory channels = new bytes32[](1);
        channels[0] = channelHash;        
        newItemInput[0].channels = channels;
        // generate signature for newItemsFor call
        bytes memory signature = _signNewItems(
            user.key,
            registeredUserId,
            newItemInput,
            _deadline()
        );
        // create item
        (bytes32[] memory itemHashes, address[] memory pointers) = itemRegistry.newItemsFor(
            user.addr,
            registeredUserId,
            newItemInput,
            _deadline(),
            signature
        );
        // test new item
        assertEq(itemRegistry.itemCountForUser(registeredUserId), 1);
        assertEq(itemRegistry.dataForItem(itemHashes[0]), pointers[0]);
        assertEq(itemRegistry.isAdminForItem(itemHashes[0], registeredUserId), true);         
        assertEq(itemRegistry.addedItemToChannel(itemHashes[0], channelHash), registeredUserId); // itemid1 was added to channelid1 by userid1
        assertEq(itemRegistry.itemUri(itemHashes[0]), ipfsString);
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////  

    function _deadline() internal view returns (uint256 deadline) {
        deadline = block.timestamp + 1;
    }

    function _sign(uint256 privateKey, bytes32 digest) internal returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        sig = abi.encodePacked(r, s, v);
        assertEq(sig.length, 65);
    }                       

    function _signNewItems(
        uint256 pk,
        uint256 userId,
        ItemRegistry.NewItem[] memory newItems,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.NEW_ITEMS_TYPEHASH(), userId, newItems, deadline))
        );
        signature = _sign(pk, digest);
    }          
}
