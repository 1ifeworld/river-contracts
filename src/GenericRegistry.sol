// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ILogic} from "./interfaces/ILogic.sol";
import {Auth} from "./abstract/Auth.sol";
import {Salt} from "./abstract/Salt.sol";
import {Hash} from "./abstract/Hash.sol";

/**
 * @title GenericRegistry
 * @author Lifeworld
 */
contract GenericRegistry is Auth, Hash, Salt {  

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    error Invalid_Uid();

    mapping(uint256 userId => uint256 uidCount) public uidCountForUser;
    mapping(bytes uid => uint256 userId) public creatorOfUid;    

    function newUid(uint64 uidType, uint256 userId) external returns (bytes memory uid) {
        // increment uid count for user
        uint256 count = ++uidCountForUser[userId];
        // ser id // type // hash of user uid count ha
        uid = abi.encodePacked(userId, uidType, count);
        // set uid created by
        creatorOfUid[uid] = userId; 
    }

    function uidDetails(bytes calldata uid) public returns (uint256 userId, uint64 uidType, uint256 count) {
        if (uid.length != 72) revert Invalid_Uid();
        userId = BytesLib.toUint256(uid, 0);
        uidType = BytesLib.toUint64(uid, 32);
        count = BytesLib.toUint256(uid, 40);
    }  
}