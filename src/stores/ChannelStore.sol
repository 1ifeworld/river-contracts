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

    enum Commands {
        DATA,
        LOGIC
    }
    
    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error No_Update_Access();
    
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
    mapping(address origin => mapping(bytes32 channelUid => address pointer)) public dataForChannel;
    mapping(address origin => mapping(bytes32 channelUid => address logic)) public logicForChannel;

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
        (bytes memory channelData, address logic, bytes memory logicData) = abi.decode(data, (bytes, address, bytes));
        // Store data for channel
        address pointer = dataForChannel[sender][uid] = SSTORE2.write(channelData);
        // Set + initialize logic for channel
        _unsafeLogicInit(sender, userId, uid, logic, logicData);
        // Emit for indexing    
        emit Initialize(sender, userId, uid, pointer, logic);
    }


    // This is supposed to be called by userId/delegate post initialization. either directly or via
    //      multicall for batching purposes
    // TODO: add return abi.encoded(data for command) + decoded command provide generic return???
    function message(uint256 userId, address origin, bytes32 uid, bytes calldata data) external {
        // Check userId authorization for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);        
        // Check if user can update channelUid
        if (!IChannelLogic(logicForChannel[origin][uid]).canUpdate(userId, uid, data)) revert No_Update_Access();
        // Extract command from data
        uint8 command = uint8(data[0]);                
        // Process commands
        _unsafeProcessCommands(sender, origin, userId, uid, command, data);
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////         

    function uri(bytes32 uid) external view returns (string memory) {    
        bytes memory encodedData = SSTORE2.read(dataForChannel[msg.sender][uid]);
        address renderer = address(bytes20(encodedData));
        bytes memory data = BytesLib.slice(encodedData, 20, (encodedData.length - 20));
        return IRenderer(renderer).render(data);                        
    }     

    function getUri(address origin, bytes32 uid) external view returns (string memory) {
        bytes memory encodedData = SSTORE2.read(dataForChannel[origin][uid]);
        address renderer = address(bytes20(encodedData));
        bytes memory data = BytesLib.slice(encodedData, 20, (encodedData.length - 20));
        return IRenderer(renderer).render(data);    
    }        

    // TODO: add getters that dont rely on msg.sender

    function getReplaceAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[origin][uid]).canReplace(userId, uid, data);
    }  

    function getUpdateAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[origin][uid]).canUpdate(userId, uid, data);
    }      

    function getAddAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[origin][uid]).canAdd(userId, uid, data);
    }
    function getRemoveAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[origin][uid]).canRemove(userId, uid, data);
    }        

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////  

    function _unsafeProcessCommands(
        address sender, 
        address origin,
        uint256 userId, 
        bytes32 uid, 
        uint8 command, 
        bytes calldata data
    ) internal {
        if (command == uint8(Commands.DATA)) {
            // Decode incoming data
            (bytes memory incomingData) = abi.decode(data[1:], (bytes));
            // Store data for channel
            address pointer = dataForChannel[origin][uid] = SSTORE2.write(incomingData);
            // Emit for indexing
            emit Data(sender, origin, userId, uid, pointer);
        } else if (command == uint8(Commands.LOGIC)) {
            // Decode incoming data
            (address logic, bytes memory logicData) = abi.decode(data[1:], (address, bytes));
            // Set + initialize logic for channel
            _unsafeLogicInit(origin, userId, uid, logic, logicData);
            // Emit for indexing          
            emit Logic(sender, origin, userId, uid, logic);
        }        
    }    

    function _unsafeLogicInit(address origin, uint256 userId, bytes32 uid, address logic, bytes memory data) internal {
        logicForChannel[origin][uid] = logic;
        IChannelLogic(logic).initializeWithData(userId, uid, data);        
    }
}