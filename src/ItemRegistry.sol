// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ChannelRegistry} from "./ChannelRegistry.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";

/**
 * @title ItemRegistry
 * @author Lifeworld
 */
contract ItemRegistry {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////        

    struct NewItem {
        bytes data;
        uint256[] channels;
    }      

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////        

    error Unuathorized_Sender();
    error No_Add_Access();
    error No_Remove_Access();
    error No_Edit_Access();
    error No_Erase_Access();
    error Unauthorized_Signer_For_User(uint256 userId);  

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////           

    event NewItems(address sender, uint256 userId, uint256[] itemIds, address[] pointers); 
    event Add(address sender, uint256 userId, uint256 channelId, uint256 itemId);    
    event Remove(address sender, uint256 userId, uint256 channelId, uint256 itemId);
    event Edit(address sender, uint256 userId, uint256 itemId, address pointer);
    event Erase(address sender, uint256 userId, uint256 itemId);    

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////     

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    ChannelRegistry public channelRegistry;    
    uint256 public itemCount;
    // mapping(uint256 itemId => uint256 userId) public creatorForItem;  // could turn this into admin for item? first admin = creator?
    mapping(uint256 itemId => mapping(uint256 userId => bool status)) public adminForItem;
    mapping(uint256 itemId => address pointer) public dataForItem;
    mapping(uint256 itemId => mapping(uint256 channelId => uint256 userId)) public addedItemToChannel;
   
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

    function newItems(uint256 userId, NewItem[] memory newItemInputs) 
        public 
        returns (uint256[] memory itemIds, address[] memory pointers) 
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Setup memory arrays to return
        itemIds = new uint256[](newItemInputs.length);
        pointers = new address[](newItemInputs.length);
        // Set for loop
        for (uint256 i; i < newItemInputs.length; ++i) {
            // Increment item count
            uint256 itemId = ++itemCount;
            // Store data + creator for item      
            dataForItem[itemId] = SSTORE2.write(newItemInputs[i].data);       
            adminForItem[itemId][userId] = true;                 
            // Add item to channel(s)
            for (uint256 j; j < newItemInputs[i].channels.length; ++j) {
                if (!channelRegistry.getAddAccess(newItemInputs[i].channels[j], userId)) revert No_Add_Access();
                _unsafeAddToChannel(sender, userId, newItemInputs[i].channels[j], itemId);
            }   
            // Set memory array values for return
            itemIds[i] = itemId;
            pointers[i] = dataForItem[itemId];            
        }    
        // Emit data for indexing
        emit NewItems(sender, userId, itemIds, pointers);
    }

    // Adds existing item to an existing channel
    function add(uint256 userId, uint256 itemId, uint256 channelId) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Check for add access
        if (!channelRegistry.getAddAccess(channelId, userId)) revert No_Add_Access();
        // Add to channel      
        _unsafeAddToChannel(sender, userId, channelId, itemId);
    }

    function remove(uint256 userId, uint256 itemId, uint256 channelId) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Check for remove access
        if (userId != addedItemToChannel[userId][channelId]) {
            if (channelRegistry.getRemoveAccess(channelId, userId)) {
                revert No_Remove_Access();
            }
        } 
        // Remove from channel      
        _unsafeRemoveFromChannel(sender, userId, channelId, itemId);        
    }

    function edit(uint256 userId, uint256 itemId, bytes calldata data) external returns (address pointer) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Check that user is item creator
        if (!adminForItem[itemId][userId]) revert No_Edit_Access();        
        // Update data stored for item
        dataForItem[itemId] = pointer = SSTORE2.write(data);
        // Emit for indexing
        emit Edit(sender, userId, itemId, pointer);
    }    

    // NOTE: techincally an admin could exist post data deletion and refill the slot of the item
    //       doesnt effectively "delete" the ability to ever update an item again
    function erase(uint256 userId, uint256 itemId) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Check if user is creator for item -- NOTE potentially make this an admin based setup
        if (!adminForItem[itemId][userId]) revert No_Erase_Access();
        // Erase item
        delete dataForItem[itemId];
        // Emit for indexing
        emit Erase(sender, userId, itemId);
    }    

    /*
    *
        NOTE:
        add ability to add/remove admins on specific items
    *
    */

    // potentially add a check here to make sure the item exists
    function _unsafeAddToChannel(
        address sender, 
        uint256 userId, 
        uint256 channelId, 
        uint256 itemId
    ) internal {
        addedItemToChannel[itemId][channelId] = userId;
        emit Add(sender, userId, channelId, itemId);
    }    

    function _unsafeRemoveFromChannel(
        address sender, 
        uint256 userId, 
        uint256 channelId, 
        uint256 itemId
    ) internal {
        delete addedItemToChannel[itemId][channelId];
        emit Remove(sender, userId, channelId, itemId);
    }    

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////           

    function itemUri(uint256 itemId) public view returns (string memory uri) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[itemId]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        uri = IRenderer(renderer).render(data);
    }

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////   

    function _authorizationCheck(address account, uint256 userId) internal view returns (address) {
        // Check that sender has write access for userId
        if (account != idRegistry.custodyOf(userId) 
            && account != delegateRegistry.delegateOf(userId)
        ) revert Unauthorized_Signer_For_User(userId);          
        // Return account address as authorized sender
        return account;        
    }        
}