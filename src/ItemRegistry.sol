// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {MetadataBuilder} from "micro-onchain-metadata-utils/MetadataBuilder.sol";
import {MetadataJSONKeys} from "micro-onchain-metadata-utils/MetadataJSONKeys.sol";
import {Strings} from "openzeppelin-contracts/utils/Strings.sol";
import {ERC1155} from "openzeppelin-contracts/token/ERC1155/ERC1155.sol";

/**
 * @title IdRegstiry
 * @author Lifeworld
 */
contract IdRegistry {
    mapping(uint256 userId => address custody) public custodyOf;
    mapping(address custody => uint256 userId) public idOf;
}

/**
 * @title DelegateRegistry
 * @author Lifeworld
 */
contract DelegateRegistry {
    mapping(uint256 userId => address delegate) public delegateOf;
}

/**
 * @title ChannelRegistry
 * @author Lifeworld
 */
contract ChannelRegistry {

    error Input_Length_Mismatch();
    error No_Add_Access();
    error No_Remove_Access();        

    event Add(address itemRegistry, uint256 userId, uint256 channelId, uint256 itemId);

    enum Roles {
        NONE,
        MEMBER,
        ADMIN
    }

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    ItemRegistry public itemRegistry

    constructor(address _idRegistry, address _delegateRegistry, address _itemRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
        itemRegistry = ItemRegistry(_itemRegistry);
    }
    
    uint256 public channelCount;
    mapping(uint256 channelId => uint256 creator) public creatorForChannel;
    mapping(uint256 channelId => string uri) public uriForChannel
    mapping(uint256 channelId => mapping(uint256 userId => Roles)) public rolesForChannel;
    mapping(uint256 itemId => uint256 channelId) public channelForItem;
    // Used to keep track of what user added an item to a channel
    mapping(uint256 itemId => uint256 userId) public adderForItem;
    
    function newChannel(
        uint256 userId, 
        uint256[] memory participants,
        Roles[] memory roles,
        string memory uri
    ) public returns (uint256 channelId) {
        // Cache msg.sender
        address sender = msg.sender
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();        
        // Increment channel count
        channelId = ++channelCount;
        // Setup channel
        creatorForChannel[channelId].creator = userId;
        uriForChannel[channelId].uri = uri;
        if (participants.length != roles.length) revert Input_Length_Mismatch();
        for (uint256 i; i < participants.length; ++i) {
            rolesForChannnel[channelId][participants[i] = roles[i]];
        }
        // Emit for indexing
        emit NewChannel(sender, userId, channelId, participants, roles, uri); 
    }

    // NOTE: All adds must come via itemRegistry
    // 
    // NOTE: might need to make the itemIds some hash of ItemRegistry + ItemId (to allow for redundant numbers)
    function add(uint256 userId, uint256 channelId, uint256 itemId) public {
        // Cache msg.sender
        address sender = msg.sender
        // Check that sender was valid itemRegistry
        if (sender != address(itemRegistry)) revert Unuathorized_Sender();        
        // Check add access
        if (rolesForChannel[channelId][userId] < Roles.MEMBER) revert No_Add_Access();
        // Add item to channel
        channelForItem[itemId] = channelId;
        adderForItem[itemId] = userId;
        // Emit for indexing
        emit Add(sender, userId, channelId, itemId);
    }

    function remove(uint256 userId, uint256 channelId, uint256 itemId) public {
        // Cache msg.sender
        address sender = msg.sender
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();   
        // Check remove access
        if (adderForItem[itemId] != userId && rolesForChannel[channelId][userId] < Roles.ADMIN) revert No_Remove_Access();        
        // Remove item from channel
        delete channelForItem[itemId];
        // Emit for indexing
        emit Remove(sender, userId, uint256 channelId, uint256 itemId);
    }
}

/**
 * @title ItemRegistry
 * @author Lifeworld
 */
contract ItemRegistry {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////        

    error Unuathorized_Sender();
    error No_Add_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////            

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////            

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    ChannelRegistry public channelRegistry;    

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////      

    uint256 public itemCount;
    mapping(uint256 itemId => address pointer) public pointerForItem;
    mapping(uint256 itemId => uint256 userId) public creatorForItem;     

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

    function newItem(uint256 userId, bytes calldata data, uint256[] memory channels) public returns (uint256 itemId) {
        // Cache msg.sender
        address sender = msg.sender
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();        
        // Increment item count
        itemId = ++itemCount;
        // Store data for item
        pointerForItem[itemId] = SSTORE2.write(data)
        // Store creator for item
        creatorForItem[id] = userId;     
        // Add item to channel(s)
        for (uint256 i; i < channels.length; ++i) {
            channelRegistry.add(userId, channels[i], itemId);            
        }            
        // Emit data for indexing
        emit NewItem(sender, userId, itemId)
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////           
}