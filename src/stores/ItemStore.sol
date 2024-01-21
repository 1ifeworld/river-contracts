// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";
import {ChannelStore} from "./ChannelStore.sol";
import {Auth} from "../abstract/Auth.sol";
import {IRenderer} from "../interfaces/IRenderer.sol";
import {IStore} from "../interfaces/IStore.sol";
import {IChannelLogic} from "../interfaces/IChannelLogic.sol";
import {IChannelStore} from "../interfaces/IChannelStore.sol";

contract ItemStore is Auth {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////

    enum Commands {
        ADMIN,
        DATA,
        ADD,
        REMOVE
    }
    struct Channel {
        address store;
        address origin;
        bytes32 uid;
        bytes data;
    }    
    
    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error OnlyAdmin();
    error No_Add_Access();
    error No_Remove_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    event Initialize(address origin, uint256 userId, bytes32 itemUid, address pointer);
    event Data(address origin, uint256 userId, bytes32 itemUid, address pointer);
    event Admin(address origin, uint256 userId, bytes32 itemUid, uint256 admin);
    // event Add(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
    event Remove(address origin, uint256 userId, bytes32 itemUid, bytes32 channelUid);
    event Add(address sender, address origin, uint256 userId, bytes32 itemUid, address channelStore, uint256 channelOrigin, bytes32 channelUid);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    mapping(address origin => mapping(bytes32 item => address pointer)) public dataForItem;    
    mapping(address origin => mapping(bytes32 item => uint256 admin)) public adminForItem; 
    mapping(address origin => mapping(bytes32 item => mapping(bytes32 channel => uint256 userId))) addedItemToChannel;

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////

    constructor(address _idRegistry, address _delegateRegistry) {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }    

    //
    function initializeWithData(uint256 userId, bytes32 uid, bytes calldata data) external {
        // Cache msg.sender
        address sender = msg.sender;
        // Decode incoming data
        (
            bytes memory itemData,
            Channel[] memory channels
        ) = abi.decode(data, (bytes, Channel[]));
        // Store item data
        address pointer = dataForItem[sender][uid] = SSTORE2.write(itemData);
        // Set item admin (temporary, will be replaced with arbitrary logic / multi admin approach)
        // NOTE: will want to filter out add events where the sender is River.sol to prevent spam
        adminForItem[sender][uid] = userId;
        // Initialize item
        emit Initialize(sender, userId, uid, pointer);        
        // Process adds
        for (uint256 i; i < channels.length; ++i) {
            // Check user for add access + process add
            _unsafeAdd(userId, sender, uid, channel);
        }
    }


    function add(uint256 userId, address origin, bytes32 itemUid, Channels[] memory channels) {
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);     
        // Check user for add access + process add
    }

    function _unsafeAdd(
        uint256 userId, 
        address origin,         
        bytes32 itemUid,
        Channel memory channel        
    ) internal {
        // Check for access 
        if (!IChannelStore(channel.store).getAddAccess(
            userId, 
            channel.origin, 
            channel.uid, 
            channel.data
        )) revert No_Add_Access();
        // Add item to channel
        addedItemToChannel[origin][itemUid][channel.uid] = userId;
        // Emit for indexing
        emit Add(origin, userId, itemUid, channel.store, channel.origin, channel.uid);
    }

    // function _unsafeAdd(
    //     address sender, 
    //     uint256 userId, 
    //     Channel memory channel
    // ) internal {
    //     if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();        
    //     addedItemToChannel[itemHash][channelHash] = userId;
    //     emit Add(sender, userId, itemHash, channelHash);
    // }           



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
    function uri(bytes32 itemUid) external view returns (string memory) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[msg.sender][itemUid]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        return IRenderer(renderer).render(data);
    }   
    //
    function getUri(address origin, bytes32 itemUid) external view returns (string memory) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[origin][itemUid]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        return IRenderer(renderer).render(data);
    }       
}