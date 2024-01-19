// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";
import {ILogic} from "./interfaces/ILogic.sol";
import {ChannelRegistrySignatures} from "./abstract/signatures/ChannelRegistrySignatures.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Auth} from "./abstract/Auth.sol";
import {Salt} from "./abstract/Salt.sol";
import {Hash} from "./abstract/Hash.sol";

/**
 * @title ChannelRegistry
 * @author Lifeworld
 */
contract ChannelRegistry is ChannelRegistrySignatures, Auth, Hash, Salt {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////        

    error No_Update_Access();    

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////        

    // event NewChannel(address sender, uint256 userId, bytes32 channelHash, string uri, address logic);
    event NewChannel(address sender, uint256 userId, bytes32 channelHash, address pointer, address logic);
    event UpdateData(address sender, uint256 userId, bytes32 channelHash, address pointer);
    event UpdateLogic(address sender, uint256 userId, bytes32 channelHash, address logic);

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////   
    
    bytes32 public constant NEW_CHANNEL_TYPEHASH =
        keccak256("NewChannel(uint256 userId,address logic,uint256 deadline)");       

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////    

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    mapping(uint256 userId => uint256 channelId) public channelCountForUser;    
    mapping(bytes32 channelHash => string uri) public uriForChannel;
    mapping(bytes32 channelHash => address pointer) public dataForChannel;
    mapping(bytes32 channelHash => address logic) public logicForChannel;    

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////        

    constructor(address _idRegistry, address _delegateRegistry) EIP712("ChannelRegistry", "1") {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
    }

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////  

    // NOTE: potentially consider returning the data pointer too? this done in itemRegistry
    function newChannel(
        uint256 userId, 
        // string calldata uri,
        bytes calldata data,
        address logic,
        bytes calldata logicInit
    ) public returns (bytes32 channelHash) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create new channel
        channelHash = _unsafeNewChannel(sender, userId, data, logic, logicInit);
    }

    function updateChannelData(uint256 userId, bytes32 channelHash, bytes calldata data) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);   
        // Check if user can update channel logic
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel data
        address pointer = dataForChannel[channelHash] = SSTORE2.write(data);
        // Emit for indexing
        emit UpdateData(sender, userId, channelHash, pointer);                    
    }          

    function updateChannelLogic(uint256 userId, bytes32 channelHash, address logic, bytes calldata logicInit) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);   
        // Check if user can update channel logic
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel logic
        logicForChannel[channelHash] = logic;
        ILogic(logic).initializeWithData(userId, channelHash, logicInit);       
        // Emit for indexing
        emit UpdateLogic(sender, userId, channelHash, logic);                    
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////      

    function channelUri(bytes32 channelHash) public view returns (string memory uri) {
        bytes memory encodedBytes = SSTORE2.read(dataForChannel[channelHash]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        uri = IRenderer(renderer).render(data);
    }    

    function getAddAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canAdd(userId, channelHash);
    }

    function getRemoveAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {     
        return ILogic(logicForChannel[channelHash]).canRemove(userId, channelHash);
    }      

    function getUpdateAccess(uint256 userId, bytes32 channelHash) public view returns (bool) {
        return ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash);
    }    

    function generateChannelHash(uint256 userId, uint256 channelId) external pure returns (bytes32 channelhash) {
        channelhash = _generateHash(userId, channelId, CHANNEL_SALT);
    } 

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////  

    function _unsafeNewChannel(
        address sender,
        uint256 userId,
        bytes calldata data,
        address logic,
        bytes calldata logicInit
    ) internal returns (bytes32 channelHash) {
        // Increment user channel count + generate channelHash
        channelHash = _generateHash(userId, ++channelCountForUser[userId], CHANNEL_SALT);   
        // Store channel data
        address pointer = dataForChannel[channelHash] = SSTORE2.write(data);         
        // Setup channel logic
        logicForChannel[channelHash] = logic;
        ILogic(logic).initializeWithData(userId, channelHash, logicInit);        
        // Emit for indexing
        emit NewChannel(sender, userId, channelHash, pointer, logic);         
    }

    // function _add(
    //     address sender, 
    //     uint256 userId, 
    //     bytes32 itemHash,
    //     bytes32 channelHash
    // ) internal {
    //     if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();        
    //     addedItemToChannel[itemHash][channelHash] = userId;
    //     emit Add(sender, userId, itemHash, channelHash);
    // }           
}