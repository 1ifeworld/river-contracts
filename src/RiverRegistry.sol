// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {EnumberableKeySet} from "./libraries/EnumberableKeySet.sol";
import {IMetadataValidator} from "./interfaces/IMetadataValidator.sol";
import {Trust2} from "./abstract/Trust2.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Signatures} from "./abstract/Signatures.sol";

/**
 * @title RiverRegistry
 */
contract RiverRegistry is Trust2, Nonces {
    using EnumerableKeySet for KeySet;
    
    ////////////////////////////////////////////////////////////////
    // ERRORS (move these into interface later)
    ////////////////////////////////////////////////////////////////       

    error Past_Migration_Cutoff();
    error Already_Migrated();

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
    event Migrate(indexed uint256 id);    

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
        uint32 keyType,
        bytes calldata key,
        // uint8 metadataType,
        // bytes calldata metadata
    }

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
    IdRegistryLike public idRegistry;    
    mapping(uint256 rid => KeySet activeKeys) internal _activeKeysByRid;
    mapping(uint256 rid => KeySet removedKeys) internal _removedKeysByRid;    
    mapping(uint256 rid => mapping(bytes key => KeyData data)) public keys;    
    mapping(uint32 keyType => mapping(uint8 metadataType => IMetadataValidator validator)) public validators; 

    ////////////////////////////////////////////////////////////////
    // CONSTRUCTOR
    ////////////////////////////////////////////////////////////////      

    construtor(
        address initialOwner,
        address[] memory initialTrustedCallers,
    ) Trust2(initialOwner), EIP712("RiverRegistry", "1") {
        // other stuff
        _setTrusted(initialTrustedCallers);
    }  

    ////////////////////////////////////////////////////////////////
    // MIGRATION MANAGEMENT
    ////////////////////////////////////////////////////////////////      

    // NOTE: do a test in foundry to understand if we can actually process
    //       all the registers in one call or if we wanna split out to diff txns, etc
    function trustedPrepMigration(address memory to, address recovery) onlyTrusted {
        // Revert if targeting an rid after migration cutoff
        if (rid > RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Process register without sig checks
        _register(to, recovery);
    }

    // TODO: should we add in a "already migrated" storage variable
    //       that would prevent an rid from being migrated more than once?
    //       quick answer is yes, but would mean if we mess up we have to redeploy the contract again while prod
    //       is live :(
    //       UPDATE: added the above ^ in because we should be able to not mess this up, plus can
    //               always trigger a change through recovery flow in emergency
    function trustedMigrateFor(uint256 rid, address recipient, address recovery, KeyRegistration[] memory keys) onlyTrusted external {
        // Revert if targeting an rid after migration cutoff
        if (rid > RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Revert if rid has already migrated
        if (hasMigrated[rid]) revert Already_Migrated();        

        // check that rid is currently registered, and that recipient doesnt own rid
        address fromCustody = _validateMigration(rid, recipient);
        // transfer rid
        _unsafeTransfer(rid, fromCustody, recipeint)
        // change recovery addresss
        _unsafeChangeRecovery(rid, recovery);

        // Add keys
        for (uint256 i; i < keys.length; ++i) {
            _add(rid, keys[i].keyType, keys[i].key, 0, new bytes(0))
        }

        // update migration state for rid
        hasMigrated[rid] = true;
        emit Migrate(rid);
    }

    ////////////////////////////////////////////////////////////////
    // ID MANAGEMENT
    ////////////////////////////////////////////////////////////////

    
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
     * @dev Change recovery address without checking invariants.
     * @dev Will revert if contract is paused
     */
     // add back in pausing ??
    function _unsafeChangeRecovery(uint256 id, address recovery) internal {
        /* Change the recovery address */
        recoveryOf[id] = recovery;

        emit ChangeRecoveryAddress(id, recovery);
    }    

    /**
     * @dev Retrieve custody and validate rid/recipient
     */
    function _validateMigration(uint256 rid, address to) internal view returns (address fromCustody) {
        fromCustody = custodyOf[rid];
        // Revert if rid not registered
        if (fromCustody == address(0)) revert Has_No_Id();
        // Revert if recipient already has rid
        if (idOf[to] != 0) revert Has_Id();
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
    // VIEWS
    ////////////////////////////////////////////////////////////////        

    ////////////////////////////////////////////////////////////////
    // SIGNATURE HELPERS
    ////////////////////////////////////////////////////////////////                         
}