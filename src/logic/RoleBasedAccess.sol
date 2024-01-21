// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";
import {Auth} from "../abstract/Auth.sol";
import {ILogic} from "../interfaces/ILogic.sol";

/**
 * @title RoleBasedAccess
 * @author Lifeworld 
 */
contract RoleBasedAccess is ILogic, Auth {

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
    error Only_Admin();  

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////  

    event RolesSet(address sender, address origin, uint256 userId, uint256[] targetUserIds, bytes32 channelHash, Roles[] roles);
    
    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////  

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    mapping(address origin => mapping(uint256 userId => mapping(bytes32 channelUid => Roles))) public userRoleForChannel;

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

    function initializeWithData(uint256 userId, bytes32 channelUid, bytes memory data) external {
        // Cache msg.sender
        address sender = msg.sender;     
        // Decode incoming data
        (
            uint256[] memory targetUserIds,
            Roles[] memory roles
        ) = abi.decode(data, (uint256[], Roles[]));
        // Check for valid inputs
        if (targetUserIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < targetUserIds.length; ++i) {
            userRoleForChannel[sender][targetUserIds[i]][channelUid] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, sender, userId, targetUserIds, channelUid, roles);
    }
    
    function editRoles(address origin, uint256 userId, uint256[] memory targetUserIds, bytes32 channelUid, Roles[] memory roles) external {  
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check for valid inputs
        if (targetUserIds.length != roles.length) revert Input_Length_Mismatch();
        // Set roles
        for (uint256 i; i < targetUserIds.length; ++i) {
            if (userRoleForChannel[origin][targetUserIds[i]][channelUid] < Roles.ADMIN) revert Only_Admin();
            userRoleForChannel[origin][targetUserIds[i]][channelUid] = roles[i];
        }
        // Emit for indexing
        emit RolesSet(sender, origin, userId, targetUserIds, channelUid, roles);        
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////    

    function updateAccess(uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[msg.sender][userId][uid] < Roles.ADMIN ? false : true;
    }        
    function addAccess(uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[msg.sender][userId][uid] < Roles.MEMBER ? false : true;
    }
    function removeAccess(uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[msg.sender][userId][uid] < Roles.ADMIN ? false : true;
    }

    function getUpdateAccess(address origin, uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[origin][userId][uid] < Roles.ADMIN ? false : true;
    }    
    function getAddAccess(address origin, uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[origin][userId][uid] < Roles.MEMBER ? false : true;
    }    
    function getRemoveAccess(address origin, uint256 userId, bytes32 uid) external view returns (bool) {
        return userRoleForChannel[origin][userId][uid] < Roles.ADMIN ? false : true;
    }    
}