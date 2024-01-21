// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IStore} from "../interfaces/IStore.sol";
import {IRenderer} from "../interfaces/IRenderer.sol";
import {IChannelLogic} from "../interfaces/IChannelLogic.sol";

/**
 * @title ChannelStore
 * @author Lifeworld
 */
contract ChannelStore is IStore {

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

    event Initialize(address origin, uint256 userId, bytes32 uid, address pointer, address logic);
    event Data(address origin, uint256 userId, bytes32 uid, address pointer);
    event Logic(address origin, uint256 userId, bytes32 uid, address logic);
    
    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    mapping(address origin => mapping(bytes32 channelUid => address pointer)) public dataForChannel;
    mapping(address origin => mapping(bytes32 channelUid => address logic)) public logicForChannel;
    
    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////

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

    // TODO: add return abi.encoded(data for command) + decoded command provide generic return???
    function message(uint256 userId, bytes32 uid, bytes calldata data) external {
        // Cache msg.sender
        address sender = msg.sender;
        // Check if user can update channelUid
        if (!IChannelLogic(logicForChannel[sender][uid]).canUpdate(userId, uid, data)) revert No_Update_Access();
        // Extract command from data
        uint8 command = uint8(data[0]);                
        // Process commands
        _unsafeProcessCommands(sender, userId, uid, command, data);
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

    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[msg.sender][uid]).canReplace(userId, uid, data);
    }  

    function getUpdateAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[msg.sender][uid]).canUpdate(userId, uid, data);
    }      

    function getAddAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[msg.sender][uid]).canAdd(userId, uid, data);
    }
    function getRemoveAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool) {
        return IChannelLogic(logicForChannel[msg.sender][uid]).canRemove(userId, uid, data);
    }        

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////  

    function _unsafeProcessCommands(
        address sender, 
        uint256 userId, 
        bytes32 uid, 
        uint8 command, 
        bytes calldata data
    ) internal {
        if (command == uint8(Commands.DATA)) {
            // Decode incoming data
            (bytes memory incomingData) = abi.decode(data[1:], (bytes));
            // Store data for channel
            address pointer = dataForChannel[sender][uid] = SSTORE2.write(incomingData);
            // Emit for indexing
            emit Data(sender, userId, uid, pointer);
        } else if (command == uint8(Commands.LOGIC)) {
            // Decode incoming data
            (address logic, bytes memory logicData) = abi.decode(data[1:], (address, bytes));
            // Set + initialize logic for channel
            _unsafeLogicInit(sender, userId, uid, logic, logicData);
            // Emit for indexing          
            emit Logic(sender, userId, uid, logic);
        }        
    }    

    function _unsafeLogicInit(address sender, uint256 userId, bytes32 uid, address logic, bytes memory data) internal {
        logicForChannel[sender][uid] = logic;
        IChannelLogic(logic).initializeWithData(userId, uid, data);        
    }
}