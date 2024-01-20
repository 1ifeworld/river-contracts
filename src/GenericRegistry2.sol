// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";

interface IStore {
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external;
    function write(uint256 userId, bytes32 uid, bytes calldata data) external;
    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory data) external returns (bool);
    function getWriteAccess(uint256 userId, bytes32 uid, bytes memory data) external returns (bool);
}

// interface ILogic {
//     function initialize(uint256 userId,)
// }

contract ChannelStore {
    error OnlyRegistry();
    error OnlyAdmin();
    GenericRegistry constant public genericRegistry = 0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5;
    mapping(bytes32 uid => string uri) public uriForUid;
    mapping(bytes32 uid => address admin) public adminForUid;
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external {
        if (msg.sender != address(genericRegistry)) revert OnlyRegistry();
        (string memory uri, address admin) = abi.decode(data, (string, address));
        uriForUid[uid] = uri;
        adminFor[uid] = adminForUid;
    }
    // could add a command slicer to this to allow for multiple write pathways
    // can return abi.encoded(data for pathway) + the flag thats decoded to provide generic return
    function write(uint256 userId, bytes32 uid, bytes calldata data) external {
        if (adminForUid[uid] != userId) revert OnlyAdmin();
        if (data[0:1] == 0) {
            (string memory newUri) = abi.encode(data[1:], (string));
            uriForUid[uid] = newUri;
        } else {
            (address newAdmin) = abi.encode(data[1:], (string));
            adminForUid[uid] = newAdmin;            
        }
    }
}

contract ItemStore {
    error OnlyRegistry();
    error OnlyAdmin();
    GenericRegistry constant public genericRegistry = 0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5;
    ChannelStore constant public channelStore = 0x15222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5;
    // mapping(bytes32 uid => string uri) public uriForUid;
    // mapping(bytes32 uid => address admin) public adminForUid;
    // function initialize(uint256 userId, bytes32 uid, bytes calldata data) external {
    //     if (msg.sender != address(genericRegistry)) revert OnlyRegistry();
    //     (string memory uri, address admin) = abi.decode(data, (string, address));
    //     uriForUid[uid] = uri;
    //     adminFor[uid] = adminForUid;
    // }
    // could add a command slicer to this to allow for multiple write pathways
    // can return abi.encoded(data for pathway) + the flag thats decoded to provide generic return
    // function write(uint256 userId, bytes32 uid, bytes calldata data) external {
    //     if (adminForUid[uid] != userId) revert OnlyAdmin();
    //     if (data[0:1] == 0) {
    //         (string memory newUri) = abi.encode(data[1:], (string));
    //         uriForUid[uid] = newUri;
    //     } else {
    //         (address newAdmin) = abi.encode(data[1:], (string));
    //         adminForUid[uid] = newAdmin;            
    //     }
    // }
}

/**
 * @title GenericRegistry2
 * @author Lifeworld
 */
contract GenericRegistry is Auth {
    struct Update {
        bytes32 uid;
        uint8 flag;
        bytes data;
    }

    error Invalid_Uid();
    error No_Data_Access();
    error No_Replace_Access();
    error No_Write_Access();

    event NewUid(address sender, uint256 userId, bytes32 uid, address pointer);
    // this new store event should instead be listend to in the stores themselves
    event NewStore(address sender, uint256 userId, bytes32 uid, address newStore);

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;

    uint256 public uidCount; // maybe want to make this user specific for ddos?
    mapping(bytes32 uid => address data) public storeForUid;
    mapping(bytes32 uid => uint256 userId) public creatorForUid;

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    // NOTE: can add sig based version of this func as well
    function newUids(uint256 userId, bytes[] calldata inits)
        external
        returns (bytes32[] memory uids, address[] memory stores)
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // increment global uid count
        uint256 count = ++uidCount;
        // Create uids
        for (uint256 i; i < inits.length; ++i) {
            // Set uid hash
            uids[i] = keccak256(abi.encodePacked(userId, count));
            // set uid created by
            creatorForUid[uids[i]] = userId;
            // init data for uid
            stores[i] = storeForUid[uids[i]] = BytesLib.toAddress(inits[i][0:20], 0);
            IStore(stores[i]).initialize(userId, uids[i], inits[i][20:]);
            // Emit for indexing
            emit NewUid(sender, userId, uids[i], stores[i]);
        }
    }

    // NOTE: can add sig based version of this func as well
    function updateUids(uint256 userId, Update[] calldata updates)
        external
        returns (bytes32[] memory uids, address[] memory stores)
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);

        for (uint256 i; i < updates.length; ++i) {
            // check if uid exists
            if (creatorForUid[updates[i].uid] == 0) revert Invalid_Uid();
            // REPLACE logic = 0, WRITETO logic = 1
            // should make writeTo the first check since will be more often            
            if (updates[i].flag == 0) {
                // Extract logic module from uid data
                IStore store = IStore(dataForUid[updates[i].uid]);
                // Check if user has access to replace store for uid
                if (!store.getReplaceAccess(userId, updates[i].uid, updates[i].data)) revert No_Replace_Access(); 
                // Extract newStore address             
                address newStore = storeForUid[updates[i].uid] = BytesLib.toAddress(updates[i].data[0:20], 0);
                // Set new store + initialize it
                IStore(newStore).initialize(userId, updates[i].uid, updates[i].data[20:]);                                         
            } else { // WRITE TO BELOW
                // Extract logic module from uid data
                IStore store = IStore(dataForUid[updates[i].uid]);
                // Check if user has access to write to store
                if (!store.getWriteAccess(userId, updates[i].uid, updates[i].data)) revert No_Write_Access();
                // Write to store
                store.write(userId, updates[i].uid, updates[i].data);
            }
        }
    }    
}