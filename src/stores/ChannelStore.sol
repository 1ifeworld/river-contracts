// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";
import {Auth} from "../abstract/Auth.sol";
import {IRenderer} from "../interfaces/IRenderer.sol";
import {IStore} from "../interfaces/IStore.sol";

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
    function message(uint256 userId, bytes32 uid, bytes calldata data) external {
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
    function getMessageAccess(uint256 userId, bytes32 uid, bytes memory /*data*/) external view returns (bool) {
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