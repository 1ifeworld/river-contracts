// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";

/**
 * @title RoleBasedAccess
 * @author Lifeworld 
 */
contract RoleBasedAccess {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////      

    enum Roles {
        NONE,
        MEMBER,
        ADMIN
    }    

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////  

    error Input_Length_Mismatch();  
    error Unauthorized_Signer_For_User(uint256 userId);
    error Only_Admin();  

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////  

    event RolesSet(address sender, uint256 userId, uint256 channelId, uint256[] userIds, Roles[] roles);
    
    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////  

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    mapping(address target => mapping(uint256 channelId => mapping(uint256 userId => Roles))) public rolesForChannel;

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

    function initializeWithData(uint256 userId, uint256 channelId, bytes memory data) external {
        // Cache msg.sender
        address sender = msg.sender;     
        // Decode incoming data
        (
            uint256[] memory userIds,
            Roles[] memory roles
        ) = abi.decode(data, (uint256[], Roles[]));
        // Check for valid inputs
        if (userIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < userIds.length; ++i) {
            rolesForChannel[sender][channelId][userIds[i]] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, userId, channelId, userIds, roles);
    }
    
    // NOTE: have weird thing where you need to specify target since initializeWithData route 
    //       means setting that as base variable for mapping
    function editRoles(address target, uint256 userId, uint256 channelId, uint256[] memory userIds, Roles[] memory roles) external {  
        // Cache msg.sender
        address sender = msg.sender;         
        // Check that sender has write access for userId
        if (sender != idRegistry.custodyOf(userId) 
            && sender != delegateRegistry.delegateOf(userId)
        ) revert Unauthorized_Signer_For_User(userId);          
        // Check for valid inputs
        if (userIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < userIds.length; ++i) {
            if (rolesForChannel[target][channelId][userIds[i]] < Roles.ADMIN) revert Only_Admin();
            rolesForChannel[target][channelId][userIds[i]] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, userId, channelId, userIds, roles);        
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////    

    function canAdd(uint256 channelId, uint256 userId) external view returns (bool) {
        return rolesForChannel[msg.sender][channelId][userId] < Roles.MEMBER ? false : true;
    }

    function canRemove(uint256 channelId, uint256 userId) external view returns (bool) {
        return rolesForChannel[msg.sender][channelId][userId] < Roles.ADMIN ? false : true;
    }
}