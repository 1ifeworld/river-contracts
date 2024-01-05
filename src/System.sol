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
    
    error Has_Id();

    event Register(address sender, uint256 id, address recovery);
    
    uint256 public idCount;
    mapping(uint256 userId => address custody) public custodyOf;
    mapping(address custody => uint256 userId) public idOf;
    mapping(uint256 userId  => address recovery) public recoveryOf;

    function register(address recovery) external returns (uint256 id) {
        // Cache msg.sender
        address sender = msg.sender;        
        // Revert if the sender already has an id
        if (idOf[sender] != 0) revert Has_Id();    
        // Increment idCount
        id = ++idCount;
        // Assign id 
        idOf[sender] = id;
        custodyOf[id] = sender;
        recoveryOf[id] = recovery;
        // Emit for indexing
        emit Register(sender, id, recovery);        
    }    
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
    error Unuathorized_Sender();        

    event NewChannel(address sender, uint256 userId, uint256 channelId, uint256[] participants, Roles[] roles, string uri);
    event Add(address itemRegistry, uint256 userId, uint256 channelId, uint256 itemId);
    event Remove(address itemRegistry, uint256 userId, uint256 channelId, uint256 itemId);

    enum Roles {
        NONE,
        MEMBER,
        ADMIN
    }

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    ItemRegistry public itemRegistry;

    constructor(address _idRegistry, address _delegateRegistry, address _itemRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
        itemRegistry = ItemRegistry(_itemRegistry);
    }
    
    uint256 public channelCount;
    mapping(uint256 channelId => uint256 creator) public creatorForChannel;
    mapping(uint256 channelId => string uri) public uriForChannel;
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
        address sender = msg.sender;
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();        
        // Increment channel count
        channelId = ++channelCount;
        // Setup channel
        creatorForChannel[channelId] = userId;
        uriForChannel[channelId] = uri;
        if (participants.length != roles.length) revert Input_Length_Mismatch();
        for (uint256 i; i < participants.length; ++i) {
            rolesForChannel[channelId][participants[i]] = roles[i];
        }
        // Emit for indexing
        emit NewChannel(sender, userId, channelId, participants, roles, uri); 
    }

    // NOTE: All adds must come via itemRegistry
    // 
    // NOTE: might need to make the itemIds some hash of ItemRegistry + ItemId (to allow for redundant numbers)
    function add(uint256 userId, uint256 channelId, uint256 itemId) public {
        // Cache msg.sender
        address sender = msg.sender;
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
        address sender = msg.sender;
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();   
        // Check remove access
        if (adderForItem[itemId] != userId && rolesForChannel[channelId][userId] < Roles.ADMIN) revert No_Remove_Access();        
        // Remove item from channel
        delete channelForItem[itemId];
        // Emit for indexing
        emit Remove(sender, userId, channelId, itemId);
    }

    function getRoleForChannel(uint256 channelId, uint256 userId) public view returns (Roles role) {
        return rolesForChannel[channelId][userId];
    }    
}

/**
 * @title IRenderer
 * @author Lifeworld
 */
interface IRenderer {
    function decodeUri(address pointer) external view returns (string memory);
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

    event NewItem(address sender, uint256 userId, uint256 itemId); 

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////            

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////      

    uint256 public itemCount;
    mapping(uint256 itemId => address pointer) public dataForItem;
    mapping(uint256 itemId => address renderer) public rendererForItem;
    mapping(uint256 itemId => uint256 userId) public creatorForItem;     

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////                

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////       

    struct NewItemInfo {
        address renderer;
        bytes data;
        uint256[] channels;
    }

    function newItems(uint256 userId, address channelRegistry, NewItemInfo[] memory newItemInfo) public returns (uint256[] memory itemIds, address[] memory pointers) {
        // Cache msg.sender
        address sender = msg.sender;
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unuathorized_Sender();        
        // Setup memory arrays to return
        itemIds = new uint256[](newItemInfo.length);
        pointers = new address[](newItemInfo.length);
        // Set for loop
        for (uint256 i; i < newItemInfo.length; ++i) {
            // Increment item count
            uint256 itemId = ++itemCount;
            // Store data + renderer for item
            dataForItem[itemId] = SSTORE2.write(newItemInfo[i].data);       
            rendererForItem[itemId] = newItemInfo[i].renderer;     
            // Store creator for item
            creatorForItem[itemId] = userId;                 
            // Add item to channel(s)
            for (uint256 j; j < newItemInfo[i].channels.length; ++j) {
                ChannelRegistry(channelRegistry).add(userId, newItemInfo[i].channels[i], itemId);            
            }   
            // Set memory array values for return
            itemIds[i] = itemId;
            pointers[i] = dataForItem[itemId];
            // Emit data for indexing
            emit NewItem(sender, userId, itemId);            
        }    
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////           

    function itemUri(uint256 itemId) public view returns (string memory uri) {
        return IRenderer(rendererForItem[itemId]).decodeUri(dataForItem[itemId]);
    }
}