// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";
import {Auth} from "../abstract/Auth.sol";
import {IRenderer} from "../interfaces/IRenderer.sol";
import {IChannelStore} from "../interfaces/IChannelStore.sol";
import {IChannelLogic} from "../interfaces/IChannelLogic.sol";

/**
 * @title ChannelStore
 * @author Lifeworld
 */
contract ChannelStore is Auth, IChannelStore {
    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////

    struct Settings {
        address dataPointer;
        address logic;
    }

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error No_Settings_Access();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    event Initialize(address sender, uint256 userId, bytes32 uid, address pointer, address logic);
    event Data(address sender, address origin, uint256 userId, bytes32 uid, address pointer);
    event Logic(address sender, address origin, uint256 userId, bytes32 uid, address logic);

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    mapping(address origin => mapping(bytes32 channelUid => Settings)) public settingsForChannel;

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

    // This initialize call is what lets River.sol safely initialize new uids to a store
    // no userId auth check is done here since we care about it coming in from River.sol
    //      which does a userId auth check before calling initializeWithData

    // NOTE: Can determine "valid" data by checking who the sender value is in data/logic for channel
    function initializeWithData(uint256 userId, bytes32 uid, bytes calldata data) external {
        // Cache msg.sender
        address sender = msg.sender;
        // Decode incoming data
        (bytes memory dataInit, address logic, bytes memory logicInit) = abi.decode(data, (bytes, address, bytes));
        // Store data for channel
        address pointer = _unsafeDataInit(sender, uid, dataInit);
        // Set + initialize logic for channel
        _unsafeLogicInit(sender, userId, uid, logic, logicInit);
        // Emit for indexing
        emit Initialize(sender, userId, uid, pointer, logic);
    }

    function setChannelData(uint256 userId, address origin, bytes32 channelUid, bytes calldata data) external {
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check if user has access to set channel data
        if (!IChannelLogic(settingsForChannel[origin][channelUid].logic).settingsAccess(userId, channelUid)) {
            revert No_Settings_Access();
        }
        // Store data for channel
        address pointer = _unsafeDataInit(origin, channelUid, data);
        // Emit for indexing
        emit Data(sender, origin, userId, channelUid, pointer);
    }

    function setChannelLogic(
        uint256 userId,
        address origin,
        bytes32 channelUid,
        address logic,
        bytes calldata logicInit
    ) external {
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check if user has access to set channel data
        if (!IChannelLogic(settingsForChannel[origin][channelUid].logic).settingsAccess(userId, channelUid)) {
            revert No_Settings_Access();
        }
        // Set + initialize logic for channel
        _unsafeLogicInit(sender, userId, channelUid, logic, logicInit);
        // Emit for indexing
        emit Logic(sender, origin, userId, channelUid, logic);
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    function uri(bytes32 uid) external view returns (string memory) {
        bytes memory encodedData = SSTORE2.read(settingsForChannel[msg.sender][uid].dataPointer);
        address renderer = address(bytes20(encodedData));
        bytes memory data = BytesLib.slice(encodedData, 20, (encodedData.length - 20));
        return IRenderer(renderer).render(data);
    }

    function getUri(address origin, bytes32 uid) external view returns (string memory) {
        bytes memory encodedData = SSTORE2.read(settingsForChannel[origin][uid].dataPointer);
        address renderer = address(bytes20(encodedData));
        bytes memory data = BytesLib.slice(encodedData, 20, (encodedData.length - 20));
        return IRenderer(renderer).render(data);
    }

    // TODO: add getters that dont rely on msg.sender

    /*
        ISTORE SPECIFIC
    */

    function getUpdateAccess(uint256 userId, address origin, bytes32 uid)
        external
        view
        returns (bool)
    {
        return IChannelLogic(settingsForChannel[origin][uid].logic).updateAccess(userId, uid);
    }

    /*
        CHANNEL SPECIFIC
    */

    function getAddAccess(uint256 userId, address origin, bytes32 uid, bytes memory data)
        external
        view
        returns (bool)
    {
        return IChannelLogic(settingsForChannel[origin][uid].logic).addAccess(userId, uid, data);
    }

    function getRemoveAccess(uint256 userId, address origin, bytes32 uid, bytes memory data)
        external
        view
        returns (bool)
    {
        return IChannelLogic(settingsForChannel[origin][uid].logic).addAccess(userId, uid, data);
    }

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////

    function _unsafeDataInit(address origin, bytes32 channelUid, bytes memory data) internal returns (address) {
        return settingsForChannel[origin][channelUid].dataPointer = SSTORE2.write(data);
    }

    function _unsafeLogicInit(address origin, uint256 userId, bytes32 uid, address logic, bytes memory data) internal {
        settingsForChannel[origin][uid].logic = logic;
        IChannelLogic(logic).initializeWithData(userId, uid, data);
    }
}
