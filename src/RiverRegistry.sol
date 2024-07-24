// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {EnumerableKeySet, KeySet} from "./libraries/EnumerableKeySet.sol";
import {IMetadataValidator} from "./interfaces/IMetadataValidator.sol";
import {Trust} from "./abstract/Trust.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Signatures} from "./abstract/Signatures.sol";

/**
 * @title RiverRegistry
 */
contract RiverRegistry is Trust, Nonces, EIP712 {
    using EnumerableKeySet for KeySet;
    
    ////////////////////////////////////////////////////////////////
    // ERRORS (move these into interface later)
    ////////////////////////////////////////////////////////////////       

    error Past_Migration_Cutoff();
    error Already_Migrated();
    error Has_No_Id();
    error Has_Id();
    //
    error ExceedsMaximum();
    error ValidatorNotFound(uint32 keyType, uint8 metadataType);
    error InvalidState();

    ////////////////////////////////////////////////////////////////
    // EVENTS (move these into interface later)
    ////////////////////////////////////////////////////////////////  

    event Register(address indexed to, uint256 id, address recovery);    
    event Transfer(address indexed from, address indexed to, uint256 indexed id);
    event Add(
        uint256 indexed rid,
        uint32 indexed keyType,
        bytes indexed key,
        bytes keyBytes,
        uint8 metadataType,
        bytes metadata
    );
    event Migrate(uint256 indexed id);    
    event ChangeRecoveryAddress(uint256 indexed id, address indexed recovery);

    ////////////////////////////////////////////////////////////////
    // TYPES (move these into interface later)
    ////////////////////////////////////////////////////////////////    

    enum KeyState {
        NULL,
        ADDED,
        REMOVED
    }

    struct KeyData {
        KeyState state;
        uint32 keyType;
    }

    struct KeyRegistration {
        uint32 keyType;
        bytes key;
        uint8 metadataType;
        bytes metadata;
    }

    /* NOTE: currently not in use */
    struct RegistrationParams {
        address to;
        address recovery;
        KeyRegistration[] keys;
        uint256 deadline;
        bytes sig;
    }    
    
    ////////////////////////////////////////////////////////////////
    // CONSTANTS
    ////////////////////////////////////////////////////////////////

    string public constant NAME = "RiverRegistry";

    string public constant VERSION = "2024.08.22";

    bytes32 public constant REGISTER_TYPEHASH = 
        keccak256("Register(address to,address recovery,KeyData[] keys,uint256 nonce,uint256 deadline)");     

    uint256 public constant MAX_KEYS_PER_RID = 500;

    uint256 public constant RID_MIGRATION_CUTOFF = 200;

    ////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////    

    /* Ids */
    uint256 public idCount;
    mapping(address owner => uint256 rid) public idOf;
    mapping(uint256 rid => address owner) public custodyOf;
    mapping(uint256 rid => address recovery) public recoveryOf;
    mapping(uint256 rid => bool migrated) public hasMigrated;

    /* Keys */
    mapping(uint256 rid => KeySet activeKeys) internal _activeKeysByRid;
    mapping(uint256 rid => KeySet removedKeys) internal _removedKeysByRid;    
    mapping(uint256 rid => mapping(bytes key => KeyData data)) public keys;    
    mapping(uint32 keyType => mapping(uint8 metadataType => IMetadataValidator validator)) public validators; 

    ////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////      

    constructor(
        address initialOwner,
        address[] memory initialTrustedCallers
    ) Trust(initialOwner) EIP712("RiverRegistry", "1") {
        // other stuff
        bool[] memory trues = new bool[](initialTrustedCallers.length);
        for (uint256 i; i < initialTrustedCallers.length; ++i) {
            trues[i] = true;
        }
        _setTrusted(initialTrustedCallers, trues);
    }  

    ////////////////////////////////////////////////////////////////
    // MIGRATION MANAGEMENT
    ////////////////////////////////////////////////////////////////      

    // NOTE: do a test in foundry to understand if we can actually process
    //       all the registers in one call or if we wanna split out to diff txns, etc
    function trustedPrepMigration(address to, address recovery) onlyTrusted public {
        // Revert if targeting an rid after migration cutoff
        if (idCount >= RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Process register without sig checks
        _register(to, recovery);
    }

    // TODO: should we add in a "already migrated" storage variable
    //       that would prevent an rid from being migrated more than once?
    //       quick answer is yes, but would mean if we mess up we have to redeploy the contract again while prod
    //       is live :(
    //       UPDATE: added the above ^ in because we should be able to not mess this up, plus can
    //               always trigger a change through recovery flow in emergency
    function trustedMigrateFor(uint256 rid, address recipient, address recovery, KeyRegistration[] calldata keyInit) onlyTrusted public {
        // Revert if targeting an rid after migration cutoff
        if (rid > RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Revert if rid has already migrated
        if (hasMigrated[rid]) revert Already_Migrated();        

        // check that rid is currently registered, and that recipient doesnt currently own an rid
        address fromCustody = _validateMigration(rid, recipient);
        // transfer rid
        _unsafeTransfer(rid, fromCustody, recipient);
        // change recovery addresss
        _unsafeChangeRecovery(rid, recovery);

        // Add keys
        for (uint256 i; i < keyInit.length; ++i) {
            _add(rid, keyInit[i].keyType, keyInit[i].key, keyInit[i].metadataType, keyInit[i].metadata);
        }

        // update migration state for rid
        hasMigrated[rid] = true;
        emit Migrate(rid);
    }

    /**
     * @dev Retrieve custody and validate rid/recipient
     */
     // add pausable here?
    function _validateMigration(uint256 rid, address to) internal view returns (address fromCustody) {
        // Retrieve current custody address of target rid
        fromCustody = custodyOf[rid];
        // Revert if rid not registered
        if (fromCustody == address(0)) revert Has_No_Id();
        // Revert if recipient already has rid
        if (idOf[to] != 0) revert Has_Id();
    }    

    ////////////////////////////////////////////////////////////////
    // ID MANAGEMENT
    ////////////////////////////////////////////////////////////////

    // NOTE: ideas for initial compatiability with migration flow
    // add in checks on register function to not be callable within first 200 ids?
    // add in a state variable switch that enables it to be called after first 200?

    /**
     *  REGISGTRATION
     */
    
    function _register(address to, address recovery) internal returns (uint256 rid) {
        rid = _unsafeRegister(to, recovery);
        emit Register(to, idCount, recovery);
    }

    // NOTE: add back in pausing?
    function _unsafeRegister(address to, address recovery) internal returns (uint256 rid) {
        /* Revert if the target(to) has an rid */
        if (idOf[to] != 0) revert Has_Id();
        /* Incrementing before assignment ensures that no one gets the 0 rid. */
        rid = ++idCount;
        /* Register id */
        idOf[to] = rid;
        custodyOf[rid] = to;
        recoveryOf[rid] = recovery;
    }

    /**
     *  TRANSFER
     */    

    /**
     * @dev Retrieve rid and validate sender/recipient
     */
    function _validateTransfer(address from, address to) internal view returns (uint256 fromId) {
        fromId = idOf[from];

        /* Revert if the sender has no id */
        if (fromId == 0) revert Has_No_Id();
        /* Revert if recipient has an id */
        if (idOf[to] != 0) revert Has_Id();
    }

    /**
     * @dev Transfer the rid to another address without checking invariants.
     * @dev Will revert if contract is paused     
     */
     // add back in puausing?
    function _unsafeTransfer(uint256 id, address from, address to) internal {
        idOf[to] = id;
        custodyOf[id] = to;
        delete idOf[from];

        emit Transfer(from, to, id);
    }

    /**
     *  RECOVER
     */ 

    /**
     * @dev Change recovery address without checking invariants.
     * @dev Will revert if contract is paused
     */
     // add back in pausing ??
    function _unsafeChangeRecovery(uint256 id, address recovery) internal {
        /* Change the recovery address */
        recoveryOf[id] = recovery;

        emit ChangeRecoveryAddress(id, recovery);
    }    

    ////////////////////////////////////////////////////////////////
    // KEY MANAGEMENT
    ////////////////////////////////////////////////////////////////   

    // NOTE: add back in pausing?
    function _add(
        uint256 rid,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata
    ) internal {
        _add(rid, keyType, key, metadataType, metadata, true);
    }

    // NOTE: add in key valdation functionality?? or remove for this first version
    function _add(
        uint256 rid,
        uint32 keyType,
        bytes calldata key,
        uint8 metadataType,
        bytes calldata metadata,
        bool /*validate*/
    ) internal {
        KeyData storage keyData = keys[rid][key];
        if (keyData.state != KeyState.NULL) revert InvalidState();
        if (totalKeys(rid, KeyState.ADDED) >= MAX_KEYS_PER_RID) revert ExceedsMaximum();

        // IMetadataValidator validator = validators[keyType][metadataType];
        // if (validator == IMetadataValidator(address(0))) {
        //     revert ValidatorNotFound(keyType, metadataType);
        // }

        _addToKeySet(rid, key);
        keyData.state = KeyState.ADDED;
        keyData.keyType = keyType;

        emit Add(rid, keyType, key, key, metadataType, metadata);

        // if (validate) {
        //     bool isValid = validator.validate(rid, key, metadata);
        //     if (!isValid) revert InvalidMetadata();
        // }
    }                 


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
    // VIEWS
    ////////////////////////////////////////////////////////////////        


    function totalKeys(uint256 rid, KeyState state) public view virtual returns (uint256) {
        return _keysByState(rid, state).length();
    }    


    function keyAt(uint256 rid, KeyState state, uint256 index) external view returns (bytes memory) {
        return _keysByState(rid, state).at(index);
    }


    function keysOf(uint256 rid, KeyState state) external view returns (bytes[] memory) {
        return _keysByState(rid, state).values();
    }


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


    function keyDataOf(uint256 rid, bytes calldata key) external view returns (KeyData memory) {
        return keys[rid][key];
    }


    ////////////////////////////////////////////////////////////////
    // SIGNATURE HELPERS
    ////////////////////////////////////////////////////////////////                         
}