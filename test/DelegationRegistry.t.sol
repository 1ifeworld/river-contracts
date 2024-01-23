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
import {IRoles} from "../../src/interfaces/IRoles.sol";

/*
    TODO: Missing event testing
*/

contract DelegateRegistryTest is Test {       

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
    Account public delegate;     
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
        delegateRegistry = new DelegateRegistry(address(idRegistry));          
        channelRegistry = new ChannelRegistry(address(idRegistry), address(delegateRegistry));  
        itemRegistry = new ItemRegistry(address(idRegistry), address(delegateRegistry), address(channelRegistry));  
        roleBasedAccess = new RoleBasedAccess(address(idRegistry), address(delegateRegistry));  
        stringRenderer = new StringRenderer();  
        nftRenderer = new NftRenderer();  
        relayer = makeAccount("relayer");
        user = makeAccount("user");
        delegate = makeAccount("delegate");
        malicious = makeAccount("malicious");
        vm.startPrank(user.addr);        
        // register id to user
        registeredUserId = idRegistry.register(address(0));
        // end prank
        vm.stopPrank();
    }    

    //////////////////////////////////////////////////
    // DIRECT WRITES
    //////////////////////////////////////////////////        

    function test_delegate() public {
        vm.startPrank(user.addr);
        // Prep data for delegation
        DelegateRegistry.Delegation[] memory dels = new DelegateRegistry.Delegation[](1);
        dels[0] = DelegateRegistry.Delegation({
            target: address(channelRegistry),
            selector: ChannelRegistry.newChannel.selector,
            status: true,
            delegate: delegate.addr 
        });
        // process delegates
        delegateRegistry.setDelegates(1, dels);
        // test delegate
        assertEq(delegateRegistry.isDelegate(1, delegate.addr, address(channelRegistry), ChannelRegistry.newChannel.selector), true);
    }

    function test_newChannel_delegate() public {
        vm.startPrank(user.addr);
        // Prep data for delegation
        DelegateRegistry.Delegation[] memory dels = new DelegateRegistry.Delegation[](1);
        dels[0] = DelegateRegistry.Delegation({
            target: address(channelRegistry),
            selector: ChannelRegistry.newChannel.selector,
            status: true,
            delegate: delegate.addr 
        });
        // process delegate
        delegateRegistry.setDelegates(1, dels);
        vm.stopPrank();
        vm.startPrank(delegate.addr);
        // prep create channel for user
        bytes memory channelData = abi.encodePacked(address(stringRenderer), ipfsBytes);
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = 1;
        IRoles.Roles[] memory roles = new IRoles.Roles[](1);
        roles[0] = IRoles.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        firstChannelHash = channelRegistry.newChannel(
            1,
            channelData,
            address(roleBasedAccess),
            logicInit
        );   
        // Assert channel created
        assertEq(channelRegistry.channelCountForUser(1), 1);
    }

    function test_Revert_newChannel_delegate() public {
        vm.startPrank(user.addr);
        // Prep data for delegation
        DelegateRegistry.Delegation[] memory dels = new DelegateRegistry.Delegation[](1);
        dels[0] = DelegateRegistry.Delegation({
            target: address(channelRegistry),
            selector: ChannelRegistry.updateChannelLogic.selector,
            status: true,
            delegate: delegate.addr 
        });
        // process delegate
        delegateRegistry.setDelegates(1, dels);
        vm.stopPrank();
        vm.startPrank(delegate.addr);
        // prep create channel for user
        bytes memory channelData = abi.encodePacked(address(stringRenderer), ipfsBytes);
        uint256[] memory userIds = new uint256[](1);
        userIds[0] = 1;
        IRoles.Roles[] memory roles = new IRoles.Roles[](1);
        roles[0] = IRoles.Roles.ADMIN;
        bytes memory logicInit = abi.encode(userIds, roles);
        // create new channel
        // NOTE: expeect revert delagated selector not "newChannel"
        vm.expectRevert();
        firstChannelHash = channelRegistry.newChannel(
            1,
            channelData,
            address(roleBasedAccess),
            logicInit
        );   
    }    


    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////    

    // // prep create channel for user
    // bytes memory channelData = abi.encodePacked(address(stringRenderer), ipfsBytes);
    // uint256[] memory userIds = new uint256[](1);
    // userIds[0] = registeredUserId;
    // IRoles.Roles[] memory roles = new IRoles.Roles[](1);
    // roles[0] = IRoles.Roles.ADMIN;
    // bytes memory logicInit = abi.encode(userIds, roles);
    // // create new channel
    // firstChannelHash = channelRegistry.newChannel(
    //     registeredUserId,
    //     channelData,
    //     address(roleBasedAccess),
    //     logicInit
    // );            


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
        ItemRegistry.Init[] memory newItems,
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
