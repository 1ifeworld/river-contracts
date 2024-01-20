// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {Auth} from "./abstract/Auth.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";

interface IStore {
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external;
    function write(uint256 userId, bytes32 uid, bytes calldata data) external;
    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory data) external returns (bool);
    function getWriteAccess(uint256 userId, bytes32 uid, bytes memory data) external returns (bool);
}

/*
    NOTE: Channel Store

    - Allows an external address to initialize data (ex: uri) + access (ex: admin) for a given uri
    - Permissionless write access, apps would want to know what their origins are to filter out events
      related to infra they are running
    - Initialize + Write calls need to be made by the same origin address

*/
contract ChannelStore is IStore {
    enum Commands {
        URI,
        ADMIN
    }
    //
    error OnlyAdmin();
    //
    event Initialize(address origin, uint256 userId, bytes32 uid, string uri, uint256 admin);
    event Uri(address origin, uint256 userId, bytes32 uid, string uri);
    event Admin(address origin, uint256 userId, bytes32 uid, uint256 admin);
    //
    mapping(address origin => mapping(bytes32 uid => string uri)) public uriForUid;        // this could be generic data
    mapping(address origin => mapping(bytes32 uid => uint256 admin)) public adminForUid;   // this could be generic logic 
    //
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external {
        address sender = msg.sender;
        (string memory uri, uint256 admin) = abi.decode(data, (string, uint256));
        uriForUid[sender][uid] = uri;
        adminForUid[sender][uid] = admin;
        emit Initialize(sender, userId, uid, uri, admin);
    }
    // could add a command slicer to this to allow for multiple write pathways
    // can return abi.encoded(data for pathway) + the flag thats decoded to provide generic return
    // NOTE: uid here = channel uid
    function write(uint256 userId, bytes32 uid, bytes calldata data) external {
        address sender = msg.sender;
        bytes memory dataCopy = data[0:1];
        bytes1 dataCopySpec = bytes1(dataCopy);
        uint8 commandFlag = uint8(dataCopySpec);
        if (!_isAdmin(sender, userId, uid)) revert OnlyAdmin();
        if (commandFlag == uint8(Commands.URI)) {
            (string memory newUri) = abi.decode(data[1:], (string));
            uriForUid[sender][uid] = newUri;
            emit Uri(sender, userId, uid, newUri);
        } else {
            (uint256 newAdmin) = abi.decode(data[1:], (uint256));
            adminForUid[sender][uid] = newAdmin;            
            emit Admin(sender, userId, uid, newAdmin);
        }
    }
    // 
    function _isAdmin(address sender, uint256 userId, bytes32 uid) internal view returns (bool) {
        return adminForUid[sender][uid] == userId ? true : false;
    }
    //
    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, uid);
    }
    function getWriteAccess(uint256 userId, bytes32 uid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, uid);
    }    
    //
    function getAddAccess(uint256 userId, bytes32 uid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, uid);
    }
    function getRemoveAccess(uint256 userId, bytes32 uid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, uid);
    }    
    function channelUri(address origin, bytes32 uid) external view returns (string memory uri) {
        uri = uriForUid[origin][uid];
    }    
}

contract ItemStore {
    enum Commands {
        ADMIN,
        DATA,
        ADD,
        REMOVE
    }
    struct Channel {
        address store;
        bytes32 uid;
        bytes data;
    }    
    //
    error OnlyAdmin();
    error No_Add_Access();
    error No_Remove_Access();
    //
    event Initialize(address origin, uint256 userId, bytes32 itemUid, address pointer);
    event Data(address origin, uint256 userId, bytes32 itemUid, address pointer);
    event Admin(address origin, uint256 userId, bytes32 itemUid, uint256 admin);
    event Add(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
    event Remove(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
    //
    mapping(address origin => mapping(bytes32 item => address pointer)) public dataForItem;    
    mapping(address origin => mapping(bytes32 item => uint256 admin)) public adminForItem; 
    mapping(address origin => mapping(bytes32 item => mapping(bytes32 channel => uint256 userId))) addedItemToChannel;
    //
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external {
        address sender = msg.sender;
        address pointer = dataForItem[sender][uid] = SSTORE2.write(data);
        adminForItem[sender][uid] = userId;
        emit Initialize(sender, userId, uid, pointer);
    }

    // could add a command slicer to this to allow for multiple write pathways
    // can return abi.encoded(data for pathway) + the flag thats decoded to provide generic return
    // NOTE: uid here = item uid
    function write(uint256 userId, bytes32 uid, bytes calldata data) external {
        address sender = msg.sender;
        bytes memory dataCopy = data[0:1];
        bytes1 dataCopySpec = bytes1(dataCopy);
        uint8 commandFlag = uint8(dataCopySpec);
        if (!_isAdmin(sender, userId, uid)) revert OnlyAdmin();
        if (commandFlag == uint8(Commands.ADMIN)) {
            (uint256 newAdmin) = abi.decode(data[1:], (uint256));
            adminForItem[sender][uid] = newAdmin;            
            emit Admin(sender, userId, uid, newAdmin);
        } else if (commandFlag == uint8(Commands.DATA)) {
            address pointer = dataForItem[sender][uid] = SSTORE2.write(data[1:]);
            emit Data(sender, userId, uid, pointer);
            /*
                TODO: Integrate add functionality into DATA setup call as well
            */
        } else if (commandFlag == uint8(Commands.ADD)) {
            (Channel[] memory channels) = abi.decode(data[1:], (Channel[]));
            for (uint256 i; i < channels.length; ++i) {
                if (!ChannelStore(channels[i].store).getAddAccess(userId, channels[i].uid, channels[i].data)) revert No_Add_Access(); 
                addedItemToChannel[sender][uid][channels[i].uid] = userId;
                emit Add(sender, userId, uid, channels[i].uid);
            }
        } else if (commandFlag == uint8(Commands.REMOVE)) {
            (Channel memory channel) = abi.decode(data[1:], (Channel));
            if (userId != addedItemToChannel[sender][uid][channel.uid]) {
                if (ChannelStore(channel.store).getRemoveAccess(userId, channel.uid, channel.data)) {
                    revert No_Remove_Access();
                }
            }      
            delete addedItemToChannel[sender][uid][channel.uid];
            emit Remove(sender, userId, uid, channel.uid);
        }
    }
    // 
    function _isAdmin(address sender, uint256 userId, bytes32 itemUid) internal view returns (bool) {
        return adminForItem[sender][itemUid] == userId ? true : false;
    }
    //
    function getReplaceAccess(uint256 userId, bytes32 itemUid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, itemUid);
    }
    function getWriteAccess(uint256 userId, bytes32 itemUid, bytes memory /*data*/) external view returns (bool) {
        return _isAdmin(msg.sender, userId, itemUid);
    }    
    //
    function itemUri(address origin, bytes32 itemUid) external view returns (string memory uri) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[origin][itemUid]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        uri = IRenderer(renderer).render(data);
    }   
}

/**
 * @title GenericRegistry2
 * @author Lifeworld
 */
contract GenericRegistry2 is Auth {
    struct Init {
        address store;
        bytes data;
    }    
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
    function newUids(uint256 userId, Init[] calldata inits)
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
            stores[i] = storeForUid[uids[i]] = inits[i].store;
            IStore(stores[i]).initialize(userId, uids[i], inits[i].data);
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
                IStore store = IStore(storeForUid[updates[i].uid]);
                // Check if user has access to replace store for uid
                if (!store.getReplaceAccess(userId, updates[i].uid, updates[i].data)) revert No_Replace_Access(); 
                // Extract newStore address             
                address newStore = storeForUid[updates[i].uid] = BytesLib.toAddress(updates[i].data[0:20], 0);
                // Set new store + initialize it
                IStore(newStore).initialize(userId, updates[i].uid, updates[i].data[20:]);                                         
            } else { // WRITE TO BELOW
                // Extract logic module from uid data
                IStore store = IStore(storeForUid[updates[i].uid]);
                // Check if user has access to write to store
                if (!store.getWriteAccess(userId, updates[i].uid, updates[i].data)) revert No_Write_Access();
                // Write to store
                store.write(userId, updates[i].uid, updates[i].data);
            }
        }
    }    
}