// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "./IdRegistry.sol";
import {EIP712} from "./abstract/EIP712.sol";

/**
 * @title DelegateRegistry
 * @author Lifeworld
 */
contract DelegateRegistry is EIP712 {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////    

    struct Delegation {
        address target;
        bytes4 selector;
        bool status;
        address delegate;
    }

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////    

    error Unauthorized_Signer_For_User(uint256 userId);

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////        
    
    event Delegations(address sender, uint256 userId, Delegation[]);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;

    mapping(uint256 userId => 
        mapping(address delegate => 
            mapping(address target => 
                mapping(bytes4 selector => bool status)))) public isDelegate;

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////            

    constructor(address _idRegistry) EIP712("DelegateRegistry", "1") {
        idRegistry = IdRegistry(_idRegistry);
    }        

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////   
                
    function setDelegates(uint256 userId, Delegation[] memory dels) external {
        // Cache msg.sender
        address sender = msg.sender;
        // Check authorization status for msg.sender 
        if (sender != idRegistry.custodyOf(userId)) revert Unauthorized_Signer_For_User(userId);
        // Process delegations
        for (uint256 i; i < dels.length; ++i) {
            isDelegate[userId][dels[i].delegate][dels[i].target][dels[i].selector] = dels[i].status;    
        }
        // Emit for indexing
        emit Delegations(sender, userId, dels);
    }
}   