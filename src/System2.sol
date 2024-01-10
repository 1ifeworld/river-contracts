// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";

/**
 * @title IdRegistry
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
    error Unuathorized_Sender();        

    event NewChannel(address sender, uint256 userId, uint256 channelId, uint256[] participants, Roles[] roles, string uri);

    enum Roles {
        NONE,
        MEMBER,
        ADMIN
    }

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }
    
    uint256 public channelCount;
    mapping(uint256 channelId => uint256 userId) public creatorForChannel;
    mapping(uint256 channelId => string uri) public uriForChannel;
    mapping(uint256 channelId => mapping(uint256 userId => Roles)) public rolesForChannel;
    
    // can change the "creatorForChannel" mapping into a "logicForChannel" mapping that stores
    // address of a logic contract that is initialied with generic bytes data
    // first module can be role based logic
    function newChannel(
        uint256 userId, 
        uint256[] memory participants,
        Roles[] memory roles,
        string memory uri
    ) public returns (uint256 channelId) {
        // Check authorization status for msg.sender
        address sender = Auth.authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Increment channel count
        channelId = ++channelCount;
        // Setup channel
        creatorForChannel[channelId] = userId;
        uriForChannel[channelId] = uri;
        // Check for valid inputs
        if (participants.length != roles.length) revert Input_Length_Mismatch();
        // Assign roles
        for (uint256 i; i < participants.length; ++i) {
            rolesForChannel[channelId][participants[i]] = roles[i];
        }
        // Emit for indexing
        emit NewChannel(sender, userId, channelId, participants, roles, uri); 
    }

    function getAddAccess(uint256 channelId, uint256 userId) public view returns (bool) {     
        // Return add access for given channel + user
        return rolesForChannel[channelId][userId] < Roles.MEMBER ? false : true;
    }

    function getRemoveAccess(uint256 channelId, uint256 userId) public view returns (bool) {     
        // Return remove access for given channel + user
        return rolesForChannel[channelId][userId] < Roles.ADMIN ? false : true;
    }    

    function getRole(uint256 channelId, uint256 userId) public view returns (Roles role) {
        return rolesForChannel[channelId][userId];
    }    
}

/**
 * @title IRenderer
 * @author Lifeworld
 */
interface IRenderer {
    function render(bytes memory data) external view returns (string memory uri);
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
    error No_Remove_Access();
    error No_Edit_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////           

    event NewItems(address sender, uint256 userId, uint256[] itemId, address[] pointers); 
    event Add(address sender, uint256 userId, uint256 channelId, uint256 itemId);    
    event Remove(address sender, uint256 userId, uint256 channelId, uint256 itemId);
    event Edit(address sender, uint256 userId, uint256 itemId, address pointer);

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////            

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    ChannelRegistry public channelRegistry;    

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////      

    struct NewItem {
        bytes data;
        uint256[] channels;
    }

    uint256 public itemCount;
    mapping(uint256 itemId => uint256 userId) public creatorForItem;  // could turn this into admin for item? first admin = creator?
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
        address sender = Auth.authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Setup memory arrays to return
        itemIds = new uint256[](newItemInputs.length);
        pointers = new address[](newItemInputs.length);
        // Set for loop
        for (uint256 i; i < newItemInputs.length; ++i) {
            // Increment item count
            uint256 itemId = ++itemCount;
            // Store data + creator for item      
            dataForItem[itemId] = SSTORE2.write(newItemInputs[i].data);       
            creatorForItem[itemId] = userId;                 
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
        address sender = Auth.authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check for add access
        if (!channelRegistry.getAddAccess(channelId, userId)) revert No_Add_Access();
        // Add to channel      
        _unsafeAddToChannel(sender, userId, channelId, itemId);
    }

    function remove(uint256 userId, uint256 itemId, uint256 channelId) public {
        // Check authorization status for msg.sender
        address sender = Auth.authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
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
        address sender = Auth.authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check that user is item creator
        if (creatorForItem[itemId] != userId) revert No_Edit_Access();        
        // Update data stored for item
        dataForItem[itemId] = pointer = SSTORE2.write(data);
        // Emit for indexing
        emit Edit(sender, userId, itemId, pointer);
    }    

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
}

library Auth {
    error Unauthorized_Signer_For_User(uint256 userId);
    function authorizationCheck(
        IdRegistry idRegistry, 
        DelegateRegistry delegateRegistry, 
        address account, 
        uint256 userId
    ) external view returns (address) {
        // Check that sender has write access for userId
        if (account != idRegistry.custodyOf(userId) 
            && account != delegateRegistry.delegateOf(userId)
        ) revert Unauthorized_Signer_For_User(userId);          
        // Return account address as authorized sender
        return account;
    }    
}