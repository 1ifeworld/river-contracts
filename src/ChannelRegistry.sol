// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ILogic} from "./interfaces/ILogic.sol";
import {Auth} from "./abstract/Auth.sol";
import {Salt} from "./abstract/Salt.sol";
import {Hash} from "./abstract/Hash.sol";

/**
 * @title ChannelRegistry
 * @author Lifeworld
 */
contract ChannelRegistry is Auth, Hash, Salt {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////        

    error No_Update_Access();    

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////        

    event NewChannel(address sender, uint256 userId, bytes32 channelHash, string uri, address logic);
    event UpdateUri(address sender, uint256 userId, bytes32 channelHash, string uri);
    event UpdateLogic(address sender, uint256 userId, bytes32 channelHash, address logic);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////    

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    mapping(uint256 userId => uint256 channelId) public channelCountForUser;
    mapping(bytes32 channelHash => string uri) public uriForChannel;
    mapping(bytes32 channelHash => address logic) public logicForChannel;    

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

    function newChannel(
        uint256 userId, 
        string calldata uri,
        address logic,
        bytes calldata logicInit
    ) public returns (bytes32 channelHash) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Increment user channel count + generate channelHash
        channelHash = _generateHash(userId, ++channelCountForUser[userId], CHANNEL_SALT);
        // Store channel uri
        uriForChannel[channelHash] = uri;
        // Setup channel logic
        logicForChannel[channelHash] = logic;
        ILogic(logic).initializeWithData(userId, channelHash, logicInit);
        // Emit for indexing
        emit NewChannel(sender, userId, channelHash, uri, logic); 
    }
    
    function updateChannelUri(uint256 userId, bytes32 channelHash, string calldata uri) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);   
        // Check if user can update channel logic
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel uri
        uriForChannel[channelHash] = uri;     
        // Emit for indexing
        emit UpdateUri(sender, userId, channelHash, uri);                    
    }    

    function updateChannelLogic(uint256 userId, bytes32 channelHash, address logic, bytes calldata logicInit) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);   
        // Check if user can update channel logic
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel logic
        logicForChannel[channelHash] = logic;
        ILogic(logic).initializeWithData(userId, channelHash, logicInit);       
        // Emit for indexing
        emit UpdateLogic(sender, userId, channelHash, logic);                    
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////      

    function getAddAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canAdd(userId, channelHash);
    }

    function getRemoveAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canRemove(userId, channelHash);
    }      

    function getUpdateAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {
        return ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash);
    }    

    function generateChannelHash(uint256 userId, uint256 channelId) external pure returns (bytes32 channelhash) {
        channelhash = _generateHash(userId, channelId, CHANNEL_SALT);
    } 
}