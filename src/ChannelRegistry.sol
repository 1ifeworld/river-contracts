// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ILogic} from "./interfaces/ILogic.sol";

/**
 * @title ChannelRegistry
 * @author Lifeworld
 */
contract ChannelRegistry {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////     

    error Input_Length_Mismatch();  
    error Unuathorized_Sender();      
    error Unauthorized_Signer_For_User(uint256 userId);  

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////        

    event NewChannel(address sender, uint256 userId, uint256 channelId, string uri, address logic);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////    

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    uint256 public channelCount;    
    mapping(uint256 channelId => string uri) public uriForChannel;
    mapping(uint256 channelId => address logic) public logicForChannel;    

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
        bytes memory logicInit
    ) public returns (uint256 channelId) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(msg.sender, userId);
        // Increment channel count
        channelId = ++channelCount;
        // Store channel uri
        uriForChannel[channelId] = uri;
        // Setup channel logic
        logicForChannel[channelId] = logic;
        ILogic(logic).initializeWithData(userId, channelId, logicInit);
        // Emit for indexing
        emit NewChannel(sender, userId, channelId, uri, logic); 
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////      

    function getAddAccess(uint256 channelId, uint256 userId) public view returns (bool) {     
        return ILogic(logicForChannel[channelId]).canAdd(channelId, userId);
    }

    function getRemoveAccess(uint256 channelId, uint256 userId) public view returns (bool) {     
        return ILogic(logicForChannel[channelId]).canRemove(channelId, userId);
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