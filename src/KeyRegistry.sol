// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Pausable} from "@openzeppelin/utils/Pausable.sol";
import {IKeyRegistry} from "./interfaces/IKeyRegistry.sol";
import {IMetadataValidator} from "./interfaces/IMetadataValidator.sol";
import {IdRegistryLike} from "./interfaces/IdRegistryLike.sol";
import {Signatures} from "./abstract/Signatures.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {Trust} from "./abstract/Trust.sol";
import {EnumerableKeySet, KeySet} from "./libraries/EnumerableKeySet.sol";

/**
 * @title KeyRegistry
 * @author Lifeworld
 * @notice This contract is a fork of Farcaster KeyRegistry v3.1.0
 */
contract KeyRegistry is IKeyRegistry, Trust, Pausable, Signatures, EIP712, Nonces {
    using EnumerableKeySet for KeySet;

    ////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////

    string public constant NAME = "River Key Registry";

    string public constant VERSION = "2024.07.11";

    bytes32 public constant ADD_TYPEHASH = keccak256(
        "Add(address owner,uint32 keyType,bytes key,uint8 metadataType,bytes metadata,uint256 nonce,uint256 deadline)"
    );

    ////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////

    IdRegistryLike public idRegistry;    

    uint256 public maxKeysPerRid;

    /**
     * @dev Internal enumerable set tracking active keys by rid.
     */
    mapping(uint256 rid => KeySet activeKeys) internal _activeKeysByRid;

    /**
     * @dev Internal enumerable set tracking removed keys by rid.
     */
    mapping(uint256 rid => KeySet removedKeys) internal _removedKeysByRid;    

    /**
     * @dev Mapping of rid to a key to the key's data.
     *
     * @custom:param rid       The rid associated with the key.
     * @custom:param key       Bytes of the key.
     * @custom:param data      Struct with the state and key type. In the initial migration
     *                         all keys will have data.keyType == 1.
     */
    mapping(uint256 rid => mapping(bytes key => KeyData data)) public keys;    

    /**
     * @dev Mapping of keyType to metadataType to validator contract.
     *
     * @custom:param keyType      Numeric keyType.
     * @custom:param metadataType Metadata metadataType.
     * @custom:param validator    Validator contract implementing IMetadataValidator.
     */
    mapping(uint32 keyType => mapping(uint8 metadataType => IMetadataValidator validator)) public validators;    

    ////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////

    /**
     * @notice Set the IdRegistry and owner.
     *
     * @param _idRegistry       IdRegistry contract address.
     * @param _initialOwner     Initial owner address.
     * @param _maxKeysPerRid    Maximum number of keys per rid.
     *
     */
    // solhint-disable-next-line no-empty-blocks
    constructor(
        address _idRegistry,
        address _initialOwner,
        uint256 _maxKeysPerRid
    ) Trust(_initialOwner) EIP712("River KeyRegistry", "1") {
        idRegistry = IdRegistryLike(_idRegistry);
        maxKeysPerRid = _maxKeysPerRid;
        emit SetIdRegistry(address(0), _idRegistry);
        emit SetMaxKeysPerRid(0, _maxKeysPerRid);
    }

    ////////////////////////////////////////////////////////////////
    // REGISTRATION
    ////////////////////////////////////////////////////////////////

    function trustedAddFor(
        address ridOwner,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata,
        uint256 deadline,
        bytes calldata sig
    ) external onlyTrustedCaller {
        // NOTE: not perform any signature checks for rid recipient
        _add(_ridOf(ridOwner), keyType, key, metadataType, metadata);
    }        

    function add(
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata
    ) external whenNotTrustedOnly {
        _add(_ridOf(msg.sender), keyType, key, metadataType, metadata);
    }

    function addFor(
        address ridOwner,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata,
        uint256 deadline,
        bytes calldata sig
    ) external whenNotTrustedOnly {
        _verifyAddSig(ridOwner, keyType, key, metadataType, metadata, deadline, sig);
        _add(_ridOf(ridOwner), keyType, key, metadataType, metadata);
    }    


    function _add(
        uint256 rid,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata
    ) internal whenNotPaused {
        _add(rid, keyType, key, metadataType, metadata, true);
    }

    function _add(
        uint256 rid,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata,
        bool validate
    ) internal {
        KeyData storage keyData = keys[rid][key];
        if (keyData.state != KeyState.NULL) revert InvalidState();
        if (totalKeys(rid, KeyState.ADDED) >= maxKeysPerRid) revert ExceedsMaximum();

        IMetadataValidator validator = validators[keyType][metadataType];
        if (validator == IMetadataValidator(address(0))) {
            revert ValidatorNotFound(keyType, metadataType);
        }

        _addToKeySet(rid, key);
        keyData.state = KeyState.ADDED;
        keyData.keyType = keyType;
        emit Add(rid, keyType, key, key, metadataType, metadata);

        // if (validate) {
        //     bool isValid = validator.validate(rid, key, metadata);
        //     if (!isValid) revert InvalidMetadata();
        // }
    }

    ////////////////////////////////////////////////////////////////
    // MIGRATION
    ////////////////////////////////////////////////////////////////

    // TODO 

    ////////////////////////////////////////////////////////////////
    // VIEWS
    ////////////////////////////////////////////////////////////////

    /**
     * @inheritdoc IKeyRegistry
     */
    function totalKeys(uint256 rid, KeyState state) public view virtual returns (uint256) {
        return _keysByState(rid, state).length();
    }    

    /**
     * @inheritdoc IKeyRegistry
     */
    function keyAt(uint256 rid, KeyState state, uint256 index) external view returns (bytes memory) {
        return _keysByState(rid, state).at(index);
    }

    /**
     * @inheritdoc IKeyRegistry
     */
    function keysOf(uint256 rid, KeyState state) external view returns (bytes[] memory) {
        return _keysByState(rid, state).values();
    }

    /**
     * @inheritdoc IKeyRegistry
     */
    function keysOf(
        uint256 rid,
        KeyState state,
        uint256 startIdx,
        uint256 batchSize
    ) external view returns (bytes[] memory page, uint256 nextIdx) {
        KeySet storage _keys = _keysByState(rid, state);
        uint256 len = _keys.length();
        if (startIdx >= len) return (new bytes[](0), 0);

        uint256 remaining = len - startIdx;
        uint256 adjustedBatchSize = remaining < batchSize ? remaining : batchSize;

        page = new bytes[](adjustedBatchSize);
        for (uint256 i = 0; i < adjustedBatchSize; i++) {
            page[i] = _keys.at(startIdx + i);
        }

        nextIdx = startIdx + adjustedBatchSize;
        if (nextIdx >= len) nextIdx = 0;

        return (page, nextIdx);
    }

    /**
     * @inheritdoc IKeyRegistry
     */
    function keyDataOf(uint256 rid, bytes calldata key) external view returns (KeyData memory) {
        return keys[rid][key];
    }

    ////////////////////////////////////////////////////////////////
    // REMOVE
    ////////////////////////////////////////////////////////////////

    // TODO

    ////////////////////////////////////////////////////////////////
    // PERMISSIONED ACTIONS
    ////////////////////////////////////////////////////////////////

    /**
     * @inheritdoc IKeyRegistry
     */
    function setValidator(uint32 keyType, uint8 metadataType, IMetadataValidator validator) external onlyOwner {
        if (keyType == 0) revert InvalidKeyType();
        if (metadataType == 0) revert InvalidMetadataType();
        emit SetValidator(keyType, metadataType, address(validators[keyType][metadataType]), address(validator));
        validators[keyType][metadataType] = validator;
    }

    /**
     * @inheritdoc IKeyRegistry
     */
    function setIdRegistry(address _idRegistry) external onlyOwner {
        emit SetIdRegistry(address(idRegistry), _idRegistry);
        idRegistry = IdRegistryLike(_idRegistry);
    }

    /**
     * @inheritdoc IKeyRegistry
     */
    function setMaxKeysPerRid(uint256 _maxKeysPerRid) external onlyOwner {
        if (_maxKeysPerRid <= maxKeysPerRid) revert InvalidMaxKeys();
        emit SetMaxKeysPerRid(maxKeysPerRid, _maxKeysPerRid);
        maxKeysPerRid = _maxKeysPerRid;
    }    

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    ////////////////////////////////////////////////////////////////
    // RID HELPERS
    ////////////////////////////////////////////////////////////////

    function _ridOf(address ridOwner) internal view returns (uint256 rid) {
        rid = idRegistry.idOf(ridOwner);
        if (rid == 0) revert Unauthorized();
    }

    ////////////////////////////////////////////////////////////////
    // KEY SET HELPERS
    ////////////////////////////////////////////////////////////////

    function _addToKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].add(key);
    }

    function _removeFromKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].remove(key);
        _removedKeysByRid[rid].add(key);
    }

    function _resetFromKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].remove(key);
    }

    function _keysByState(uint256 rid, KeyState state) internal view returns (KeySet storage) {
        if (state == KeyState.ADDED) {
            return _activeKeysByRid[rid];
        } else if (state == KeyState.REMOVED) {
            return _removedKeysByRid[rid];
        } else {
            revert InvalidState();
        }
    }


    ////////////////////////////////////////////////////////////////
    // SIGNATURE VERIFICATION HELPERS
    ////////////////////////////////////////////////////////////////

    function _verifyAddSig(
        address ridOwner,
        uint32 keyType,
        bytes memory key,
        uint8 metadataType,
        bytes memory metadata,
        uint256 deadline,
        bytes memory sig
    ) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        ADD_TYPEHASH,
                        ridOwner,
                        keyType,
                        keccak256(key),
                        metadataType,
                        keccak256(metadata),
                        _useNonce(ridOwner),
                        deadline
                    )
                )
            ),
            ridOwner,
            deadline,
            sig
        );
    }
}