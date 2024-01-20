// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";

/**
 * @title GenericRegistry
 * @author Lifeworld
 */
contract GenericRegistry is Auth {  

    struct Update {
        bytes32 uid;
        bytes data;
    }    

    error Invalid_Uid();
    event NewUid(address sender, uint256 userId, bytes32 uid, bytes init);    
    event RequestUidUpdate(address sender, uint256 userId, bytes32 uid, bytes update);    

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    uint256 public uidCount; // maybe want to make this user specific for ddos?
    mapping(bytes32 uid => bytes init) public initForUid;
    mapping(bytes32 uid => uint256 userId) public creatorForUid;   

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }     

    function newUids(uint256 userId, bytes[] calldata uidInits) external returns (bytes32[] memory uids) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);        
        // increment uid count for user
        uint256 count = ++uidCount;
        // Create uids
        for (uint256 i; i < uidInits.length; ++i) {
            uids[i] = keccak256(abi.encodePacked(userId, count));
            // set uid created by
            creatorForUid[uids[i]] = userId;
            // set init data for uid
            initForUid[uids[i]] = uidInits[i];
            // Emit for indexing
            emit NewUid(sender, userId, uids[i], uidInits[i]);            
        }
    }

    function updateUids(uint256 userId, Update[] calldata updates) external {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);    
        // Update uids
        for (uint256 i; i < updates.length; ++i) {
            if (creatorForUid[updates[i].uid] == 0) revert Invalid_Uid();
            emit RequestUidUpdate(sender, userId, updates[i].uid, updates[i].data);
        }
    }
}