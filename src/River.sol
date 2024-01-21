// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";
import {IStore} from "./interfaces/IStore.sol";

/**
 * @title River
 * @author Lifeworld
 */
contract River is Auth {
    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////

    struct Info {
        uint256 creatorId;
        address store;
    }

    struct Init {
        address store;
        bytes data;
    }

    struct Update {
        bytes32 uid;
        address store;
        bytes data;
    }

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    // Uid is frozen or hasnt been created
    error Invalid_Uid();
    error No_Update_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    event NewUid(address sender, uint256 userId, bytes32 uid, address store);
    event UpdateUid(address sender, uint256 userId, bytes32 uid, address store);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    // TODO: determine if one global counter is an attack vector
    uint256 public uidCount;
    // TODO: determine if uids should rlly be hashes or if uint256 is better
    mapping(bytes32 uid => Info) public infoForUid;

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

    // TODO: add freeze? sets creatorForUid to 0

    // NOTE: can add sig based version of this func as well
    function newUids(uint256 userId, Init[] calldata inits) external returns (bytes32[] memory uids) {
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create uids
        for (uint256 i; i < inits.length; ++i) {
            // Increment uid count + generate/set uid hash
            uids[i] = keccak256(abi.encode(address(this), ++uidCount));
            // Set uid created by
            infoForUid[uids[i]].creatorId = userId;
            // Set + init uid store
            _unsafeStoreInit(userId, uids[i], inits[i].store, inits[i].data);
            // Emit for indexing
            emit NewUid(sender, userId, uids[i], inits[i].store);
        }
    }

    // NOTE: can add sig based version of this func as well
    function updateUids(uint256 userId, Update[] calldata updates) external {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Process updates
        for (uint256 i; i < updates.length; ++i) {
            // Check if uid exists. Will revert if frozen or doesnt exist
            if (infoForUid[updates[i].uid].creatorId == 0) revert Invalid_Uid();
            // Lookup store address for uid
            IStore store = IStore(infoForUid[updates[i].uid].store);            
            // Check if user has access to replace store for uid
            if (!store.getUpdateAccess(userId, address(this), updates[i].uid)) revert No_Update_Access();
            // Set + init uid store
            _unsafeStoreInit(userId, updates[i].uid, updates[i].store, updates[i].data);                
            // Emit for indexing
            emit UpdateUid(sender, userId, updates[i].uid, updates[i].store);
        }
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    function uri(bytes32 uid) external view returns (string memory) {
        return IStore(infoForUid[uid].store).uri(uid);
    }   

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////

    function _unsafeStoreInit(uint256 userId, bytes32 uid, address store, bytes memory data) internal {
        infoForUid[uid].store = store;
        IStore(store).initializeWithData(userId, uid, data);        
    }
}