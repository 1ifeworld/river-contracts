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

/*
    TODO: Missing event testing
*/

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
    bytes32 public firstChannelHash;
    
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
        // prep create channel for user
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = registeredUserId;
        RoleBasedAccess.Roles[] memory roles = new RoleBasedAccess.Roles[](1);
        roles[0] = RoleBasedAccess.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        firstChannelHash = channelRegistry.newChannel(
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

    function test_sigBased_newItemFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for new item
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), ipfsBytes);
        bytes32[] memory channels = new bytes32[](1);
        channels[0] = firstChannelHash;        
        newItemInput[0].channels = channels;
        // generate signature for newItemsFor call
        bytes memory signature = _signNewItemFor(
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
        assertEq(itemRegistry.addedItemToChannel(itemHashes[0], firstChannelHash), registeredUserId); // itemid1 was added to channelid1 by userid1
        assertEq(itemRegistry.itemUri(itemHashes[0]), ipfsString);
    }

    function test_sigBased_addFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for add
        bytes32 itemHash = keccak256("itemHash");
        // generate signature for addFor call
        bytes memory signature = _signAddFor(
            user.key,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline()
        );
        // add item
        itemRegistry.addFor(
            user.addr,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline(),
            signature
        );
        // test add for
        assertEq(itemRegistry.addedItemToChannel(itemHash, firstChannelHash), registeredUserId);
    }    

    function test_sigBased_batchAddFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for add
        bytes32 itemHash = keccak256("itemHash");
        bytes32[] memory channelHashes = new bytes32[](2);
        channelHashes[0] = firstChannelHash;
        channelHashes[1] = firstChannelHash;
        // generate signature for addFor call
        bytes memory signature = _signAddBatchFor(
            user.key,
            registeredUserId,
            itemHash,
            channelHashes,
            _deadline()
        );
        // addBatch
        itemRegistry.addBatchFor(
            user.addr,
            registeredUserId,
            itemHash,
            channelHashes,
            _deadline(),
            signature
        );
        // test batchAdd for
        // NOTE: a better test would try add the item to a second channel rather than a duplicate in the function
        assertEq(itemRegistry.addedItemToChannel(itemHash, firstChannelHash), registeredUserId);
    }        

    function test_sigBased_removeFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for add/remove
        bytes32 itemHash = keccak256("itemHash");
        // process add -- so it can be removed
        // generate signature for addFor call
        bytes memory addSig = _signAddFor(
            user.key,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline()
        );
        // add item
        itemRegistry.addFor(
            user.addr,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline(),
            addSig
        );        
        // proces remove
        // generate signature for removeFor call
        bytes memory removeSig = _signRemoveFor(
            user.key,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline()
        );
        // remove item
        itemRegistry.removeFor(
            user.addr,
            registeredUserId,
            itemHash,
            firstChannelHash,
            _deadline(),
            removeSig
        );
        // test add for
        // NOTE: this isnt accurately testing things because we want to see that an already item
        assertEq(itemRegistry.addedItemToChannel(itemHash, firstChannelHash), 0);
    }        

    function test_sigBased_editFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for new item
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), ipfsBytes);
        bytes32[] memory channels = new bytes32[](1);
        channels[0] = firstChannelHash;        
        newItemInput[0].channels = channels;
        // generate signature for newItemsFor call
        bytes memory signature = _signNewItemFor(
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
        // process edit
        // prep data for edit
        bytes memory newData = abi.encodePacked(address(stringRenderer), bytes("newData"));
        // generate signature for addFor call
        bytes memory editSig = _signEditFor(
            user.key,
            registeredUserId,
            itemHashes[0],
            newData,
            _deadline()
        );
        // edit item
        address pointer = itemRegistry.editFor(
            user.addr,
            registeredUserId,
            itemHashes[0],
            newData,
            _deadline(),
            editSig
        );        
        // test edit for
        assertEq(itemRegistry.dataForItem(itemHashes[0]), pointer);
        assertEq(itemRegistry.itemUri(itemHashes[0]), "newData");
    }   

    function test_sigBased_updateAdminsFor() public {
        // prank into relay -- not the user
        vm.startPrank(relayer.addr);
        // prep data for new item
        ItemRegistry.NewItem[] memory newItemInput = new ItemRegistry.NewItem[](1);
        // packs data so that [:20] == address of renderer, [20:] == bytes for renderer to decode into string
        newItemInput[0].data = abi.encodePacked(address(stringRenderer), ipfsBytes);
        bytes32[] memory channels = new bytes32[](1);
        channels[0] = firstChannelHash;        
        newItemInput[0].channels = channels;
        // generate signature for newItemsFor call
        bytes memory signature = _signNewItemFor(
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
        // process update admins
        // prep data
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = 1;
        bool[] memory statuses = new bool[](1);
        statuses[0] = false;
        // generate signature for updateAdminsFor call
        bytes memory updateAdminsForSig = _signUpdateAdminsFor(
            user.key,
            registeredUserId,
            itemHashes[0],
            userIds,
            statuses,
            _deadline()
        ); 
        // call updateAdminsFor
        itemRegistry.updateAdminsFor(
            user.addr,
            registeredUserId,
            itemHashes[0],
            userIds,
            statuses,
            _deadline(),
            updateAdminsForSig
        );
        // test updateAdminsFor for
        assertEq(itemRegistry.isAdminForItem(itemHashes[0], registeredUserId), false);  
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

    function _signNewItemFor(
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

    function _signAddFor(
        uint256 pk,
        uint256 userId,
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.ADD_TYPEHASH(), userId, itemHash, channelHash, deadline))
        );
        signature = _sign(pk, digest);
    }      

    function _signAddBatchFor(
        uint256 pk,
        uint256 userId,
        bytes32 itemHash,
        bytes32[] memory channelHashes,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.ADD_BATCH_TYPEHASH(), userId, itemHash, channelHashes, deadline))
        );
        signature = _sign(pk, digest);
    }          

    function _signRemoveFor(
        uint256 pk,
        uint256 userId,
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.REMOVE_TYPEHASH(), userId, itemHash, channelHash, deadline))
        );
        signature = _sign(pk, digest);
    }           

    function _signEditFor(
        uint256 pk,
        uint256 userId,
        bytes32 itemHash,
        bytes memory data,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.EDIT_TYPEHASH(), userId, itemHash, data, deadline))
        );
        signature = _sign(pk, digest);
    }          

    function _signUpdateAdminsFor(
        uint256 pk,
        uint256 userId,
        bytes32 itemHash,
        uint256[] memory userIds,
        bool[] memory statuses,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = itemRegistry.hashTypedDataV4(
            keccak256(abi.encode(itemRegistry.UPDATE_ADMINS_TYPEHASH(), userId, itemHash, userIds, statuses, deadline))
        );
        signature = _sign(pk, digest);
    }       
}
