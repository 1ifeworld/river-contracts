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

    event NewChannel(address sender, uint256 userId, bytes32 channelHash, address pointer, address logic);
    event UpdateData(address sender, uint256 userId, bytes32 channelHash, address pointer);
    event UpdateLogic(address sender, uint256 userId, bytes32 channelHash, address logic);

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////

    // TODO: is this a valid typehash? theres other bytes inputs that are passed in
    //       but unclear if thats worth including? since wont be readable anyway in signing flow?
    bytes32 public constant NEW_CHANNEL_TYPEHASH =
        keccak256("NewChannel(uint256 userId,address logic,uint256 deadline)");

    // TODO: is this a valid typehash? theres other bytes inputs that are passed in
    //       but unclear if thats worth including? since wont be readable anyway in signing flow?
    bytes32 public constant UPDATE_CHANNEL_DATA_TYPEHASH =
        keccak256("UpdateChannelData(uint256 userId,bytes32 channelHash,uint256 deadline)");      

    // TODO: is this a valid typehash? theres other bytes inputs that are passed in
    //       but unclear if thats worth including? since wont be readable anyway in signing flow?
    bytes32 public constant UPDATE_CHANNEL_LOGIC_TYPEHASH =
        keccak256("UpdateChannelLogic(uint256 userId,bytes32 channelHash,address logic,uint256 deadline)");                 

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
    // DIRECT WRITES
    //////////////////////////////////////////////////

    // NOTE: potentially consider returning the data pointer too? this done in itemRegistry
    function newChannel(uint256 userId, bytes calldata data, address logic, bytes calldata logicInit)
        public
        returns (bytes32 channelHash)
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create new channel
        channelHash = _unsafeNewChannel(sender, userId, data, logic, logicInit);
    }

    function updateChannelData(uint256 userId, bytes32 channelHash, bytes calldata data) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Update channel data
        _unsafeUpdateChannelData(sender, userId, channelHash, data);
    } 

    function updateChannelLogic(uint256 userId, bytes32 channelHash, address logic, bytes calldata logicInit) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Update channel logic
        _unsafeUpdateChannelLogic(sender, userId, channelHash, logic, logicInit);
    }

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////  

    function newChannelFor(
        address signer,
        uint256 userId, 
        bytes calldata data, 
        address logic, 
        bytes calldata logicInit,
        uint256 deadline,
        bytes calldata sig
    )
        public 
        returns (bytes32 channelHash)
    {
        // Verify valid transaction being generated on behalf of signer
        _verifyNewChannelSig(userId, logic, signer, NEW_CHANNEL_TYPEHASH, deadline, sig);        
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create new channel
        channelHash = _unsafeNewChannel(sender, userId, data, logic, logicInit);
    }      

    function updateChannelDataFor(
        address signer,
        uint256 userId, 
        bytes32 channelHash, 
        bytes calldata data, 
        uint256 deadline,
        bytes calldata sig
    ) public returns (address pointer) {
        // Verify valid transaction being generated on behalf of signer
        _verifyUpdateChannelDataSig(userId, channelHash, signer, UPDATE_CHANNEL_DATA_TYPEHASH, deadline, sig);
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Update channel data
        pointer = _unsafeUpdateChannelData(sender, userId, channelHash, data);        
    }

    function updateChannelLogicFor(
        address signer,
        uint256 userId, 
        bytes32 channelHash, 
        address logic,
        bytes calldata logicInit, 
        uint256 deadline,
        bytes calldata sig
    ) public  {
        // Verify valid transaction being generated on behalf of signer
        _verifyUpdateChannelLogicSig(userId, channelHash, logic, signer, UPDATE_CHANNEL_LOGIC_TYPEHASH, deadline, sig);
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Update channel logic
        _unsafeUpdateChannelLogic(sender, userId, channelHash, logic, logicInit);       
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
    
    /*
    *   NOTE:
    *   Unsafe means any no userId checks occur in this function
    *   Access control checks ARE applied in this function
    */
    
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

    function _unsafeUpdateChannelData(address sender, uint256 userId, bytes32 channelHash, bytes calldata data)
        internal
        returns (address pointer)
    {
        // Check if user can update channel data
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel data
        pointer = dataForChannel[channelHash] = SSTORE2.write(data);
        // Emit for indexing
        emit UpdateData(sender, userId, channelHash, pointer);
    }

    function _unsafeUpdateChannelLogic(
        address sender,
        uint256 userId,
        bytes32 channelHash,
        address logic,
        bytes calldata logicInit
    ) internal {
        // Check if user can update channel logic
        if (!ILogic(logicForChannel[channelHash]).canUpdate(userId, channelHash)) revert No_Update_Access();
        // Update channel logic
        logicForChannel[channelHash] = logic;
        ILogic(logic).initializeWithData(userId, channelHash, logicInit);
        // Emit for indexing
        emit UpdateLogic(sender, userId, channelHash, logic);
    } 
}
