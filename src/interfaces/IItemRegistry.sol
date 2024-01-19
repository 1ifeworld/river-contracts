
// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title IItemRegistry
 * @author Lifeworld
 */
interface IItemRegistry {    
    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////     
    struct NewItem {
        bytes data;
        bytes32[] channels;
    }      
}

