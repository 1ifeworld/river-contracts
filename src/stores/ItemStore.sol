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