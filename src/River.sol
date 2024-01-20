// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";
import {IStore} from "./interfaces/IStore.sol";

/**
 * @title River
 * @author Lifeworld
 */
contract River is Auth {
    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////

    enum Commands {
        MESSAGE,
        REPLACE
    }

    struct Init {
        address store;
        bytes data;
    }

    struct Update {
        bytes32 uid;
        Commands command;
        bytes data;
    }

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error Invalid_Uid();
    error No_Replace_Access();
    error No_Message_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    event NewUid(address sender, uint256 userId, bytes32 uid, address store);
    event Replace(address sender, uint256 userId, bytes32 uid, address store);
    event Message(address sender, uint256 userId, bytes32 uid);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    uint256 public uidCount;
    mapping(bytes32 uid => address data) public storeForUid;
    mapping(bytes32 uid => uint256 userId) public creatorForUid;

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

    // NOTE: can add sig based version of this func as well
    function newUids(uint256 userId, Init[] calldata inits) external returns (bytes32[] memory uids) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create uids
        for (uint256 i; i < inits.length; ++i) {
            // Increment uid count + generate/set uid hash
            uids[i] = keccak256(abi.encode(address(this), ++uidCount));
            // Set uid created by
            creatorForUid[uids[i]] = userId;
            // Set + init uid store
            storeForUid[uids[i]] = inits[i].store;
            IStore(inits[i].store).initialize(userId, uids[i], inits[i].data);
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
            // check if uid exists
            if (creatorForUid[updates[i].uid] == 0) revert Invalid_Uid();
            // Check command
            if (updates[i].command == Commands.MESSAGE) {
                // Lookup store address for uid
                IStore store = IStore(storeForUid[updates[i].uid]);
                // Check if user has access to message store for uid
                if (!store.getMessageAccess(userId, updates[i].uid, updates[i].data)) revert No_Message_Access();
                // Message store
                store.message(userId, updates[i].uid, updates[i].data);
                // Emit for indexing
                emit Message(sender, userId, updates[i].uid);
            } else if (updates[i].command == Commands.REPLACE) {
                // Lookup store address for uid
                IStore store = IStore(storeForUid[updates[i].uid]);
                // Check if user has access to replace store for uid
                if (!store.getReplaceAccess(userId, updates[i].uid, updates[i].data)) revert No_Replace_Access();
                // Extract + set store address from data
                address newStore = storeForUid[updates[i].uid] = address(bytes20(updates[i].data[0:20]));
                // Initialize store with data
                IStore(newStore).initialize(userId, updates[i].uid, updates[i].data[20:]);
                // Emit for indexing
                emit Replace(sender, userId, updates[i].uid, newStore);
            }
        }
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    function uri(bytes32 uid) external view returns (string memory) {
        return IStore(storeForUid[uid]).uri(uid);
    }   

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////
}
