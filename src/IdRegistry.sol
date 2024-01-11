// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title IdRegistry
 * @author Lifeworld
 */
contract IdRegistry {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////      
    
    error Has_Id();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////          

    event Register(address sender, uint256 id, address recovery);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////          
    
    uint256 public idCount;
    mapping(uint256 userId => address custody) public custodyOf;
    mapping(address custody => uint256 userId) public idOf;
    mapping(uint256 userId  => address recovery) public recoveryOf;

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////      

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