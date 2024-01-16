// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ChannelRegistry} from "./ChannelRegistry.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";
import {Auth} from "./utils/Auth.sol";
import {Hash} from "./utils/Hash.sol";
import {Salt} from "./utils/Salt.sol";

/**
 * @title ItemRegistry
 * @author Lifeworld
 */
contract ItemRegistry is Auth, Hash, Salt {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////        

    struct NewItem {
        bytes data;
        bytes32[] channels;
    }      

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////        

    error No_Add_Access();
    error No_Remove_Access();
    error Item_Not_In_Channel();
    error No_Edit_Access();
    

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////           

    event New(address sender, uint256 userId, bytes32[] itemHashes, address[] pointers); 
    event Add(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);    
    event Remove(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);
    event Edit(address sender, uint256 userId, bytes32 itemHash, address pointer); 

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////     

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    ChannelRegistry public channelRegistry;    

    mapping(uint256 userId => uint256 itemCount) public itemCountForUser;
    mapping(bytes32 itemHash => uint256 userId) public creatorForItem;
    mapping(bytes32 itemHash => mapping(uint256 userId => bool status)) public isAdminForItem;
    mapping(bytes32 itemHash => address pointer) public dataForItem;
    mapping(bytes32 itemHash => mapping(bytes32 channelHash => uint256 userId)) public addedItemToChannel;
   
    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////                

    constructor(address _idRegistry, address _delegateRegistry, address _channelRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
        channelRegistry = ChannelRegistry(_channelRegistry);
    }

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////       

    // TODO: add ability to upadte admins for a given item
    // TODO: batch add function?
    // TODO: batch edit function?
    // TODO: batch remove funciton?
    // TODO: make function(s) external?

    // NOTE: consider adding arbitrary data field to newItemInputs to enable signature based access control for channels
    function newItems(uint256 userId, NewItem[] memory newItemInputs) 
        public 
        returns (bytes32[] memory itemHashes, address[] memory pointers) 
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Setup memory arrays to return
        itemHashes = new bytes32[](newItemInputs.length);
        pointers = new address[](newItemInputs.length);
        // Set for loop
        for (uint256 i; i < newItemInputs.length; ++i) {
            // Increment user item count + generate itemhash
            itemHashes[i] = _generateHash(userId, ++itemCountForUser[userId], ITEM_SALT);
            // Store item data
            pointers[i] = dataForItem[itemHashes[i]] = SSTORE2.write(newItemInputs[i].data); 
            // Set item creator     
            isAdminForItem[itemHashes[i]][userId] = true;                                       
            // Add item to channel(s)
            for (uint256 j; j < newItemInputs[i].channels.length; ++j) {
                if (!channelRegistry.getAddAccess(userId, newItemInputs[i].channels[j])) revert No_Add_Access();
                _unsafeAddToChannel(sender, userId, itemHashes[i], newItemInputs[i].channels[j]);
            }          
        }    
        // Emit data for indexing
        emit New(sender, userId, itemHashes, pointers);
    }

    // Adds existing item to an existing channel
    // NOTE: consider adding arbitrary data field here to enable signature based access control
    function add(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check for add access
        if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();
        // Check if itemHash exists

        // Add to channel      
        _unsafeAddToChannel(sender, userId, itemHash, channelHash);
    }

    function remove(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check for remove access
        if (userId != addedItemToChannel[itemHash][channelHash]) {
            if (channelRegistry.getRemoveAccess(userId, channelHash)) {
                revert No_Remove_Access();
            }
        } 
        // Remove from channel      
        _unsafeRemoveFromChannel(sender, userId, itemHash, channelHash);        
    }

    // Passing in bytes(0) for data effectively "deletes" the contents of the item
    function edit(uint256 userId, bytes32 itemHash, bytes calldata data) external returns (address pointer) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check that user is item creator
        if (!isAdminForItem[itemHash][userId]) revert No_Edit_Access();        
        // Update data stored for item
        pointer = dataForItem[itemHash] = SSTORE2.write(data);
        // Emit for indexing
        emit Edit(sender, userId, itemHash, pointer);
    }    

    // potentially add a check here to make sure the item exists
    function _unsafeAddToChannel(
        address sender, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash
    ) internal {
        addedItemToChannel[itemHash][channelHash] = userId;
        emit Add(sender, userId, itemHash, channelHash);
    }    

    function _unsafeRemoveFromChannel(
        address sender, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash
    ) internal {
        delete addedItemToChannel[itemHash][channelHash];
        emit Remove(sender, userId, itemHash, channelHash);
    }    

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////           

    function itemUri(bytes32 itemHash) public view returns (string memory uri) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[itemHash]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        uri = IRenderer(renderer).render(data);
    }

    function generateItemHash(uint256 userId, uint256 channelId) external pure returns (bytes32 itemHash) {
        itemHash = _generateHash(userId, channelId, ITEM_SALT);
    }     
}