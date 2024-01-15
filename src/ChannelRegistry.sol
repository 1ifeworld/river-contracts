// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ILogic} from "./interfaces/ILogic.sol";
import {Salt} from "./utils/Salt.sol";
import {Hash} from "./utils/Hash.sol";

/**
 * @title ChannelRegistry
 * @author Lifeworld
 */
contract ChannelRegistry is Salt, Hash {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////     

    error Input_Length_Mismatch();  
    error Unuathorized_Sender();      
    error Unauthorized_Signer_For_User(uint256 userId);  

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////        

    event NewChannel(address sender, uint256 userId, bytes32 channelHash, string uri, address logic);

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
    
    // can change the "creatorForChannel" mapping into a "logicForChannel" mapping that stores
    // address of a logic contract that is initialied with generic bytes data
    // first module can be role based logic
    function newChannel(
        uint256 userId, 
        string calldata uri,
        address logic,
        bytes calldata logicInit
    ) public returns (bytes32 channelHash) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
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

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////      

    function getAddAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canAdd(userId, channelHash);
    }

    function getRemoveAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canRemove(userId, channelHash);
    }      

    function generateChannelHash(uint256 userId, uint256 channelId) external pure returns (bytes32 channelhash) {
        return _generateHash(userId, channelId, CHANNEL_SALT);
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