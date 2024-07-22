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

    ////////////////////////////////////////////////////////////////
    // EVENTS (move these into interface later)
    ////////////////////////////////////////////////////////////////  

    event Register(address indexed to, uint256 id, address recovery);    
    event Add(
        uint256 indexed rid,
        uint32 indexed keyType,
        bytes indexed key,
        bytes keyBytes,
        uint8 metadataType,
        bytes metadata
    );
    event Migrate(address indexed to, uint256 id, address recovery);    

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

    uint256 public immutable RID_MIGRATION_CUTOFF;

    ////////////////////////////////////////////////////////////////
    // STORAGE
    ////////////////////////////////////////////////////////////////    

    /* Ids */
    uint256 public idCount;
    mapping(address owner => uint256 rid) public idOf;
    mapping(uint256 rid => address owner) public custodyOf;
    mapping(uint256 rid => address recovery) public recoveryOf;

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
        uint256 ridMigrationCutoff
    ) Trust2(initialOwner), EIP712("RiverRegistry", "1") {
        // other stuff
        _setTrusted(initialTrustedCallers);
        RID_MIGRATION_CUTOFF = ridMigrationCutoff;
    }  

    ////////////////////////////////////////////////////////////////
    // MIGRATION MANAGEMENT
    ////////////////////////////////////////////////////////////////      

    // TODO: should we add in a "already migrated" storage variable
    //       that would prevent an rid from being migrated more than once?
    //       quick answer is yes, but would mean if we mess up we have to redeploy the contract again while prod
    //       is live :(
    function trustedMigrateFor(uint256 rid, address recipient, KeyRegistration[] memory keys) onlyTrusted external {
        // Revert if targeting an rid after migration cutoff
        if (rid > RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Revert if recipient address already owns an rid
        if (idOf[recipient] != 0) revert Has_Id();
        // Migrate rid
        idOf[to] = rid;
        custodyOf[rid] = to;
        recoveryOf[rid] = recovery;        
        emit Register(to, rid, recovery);
        // Add keys
        for (uint256 i; i < keys.length; ++i) {
            _add(rid, keys[i].keyType, keys[i].key, 0, new bytes(0))
            emit Add(rid, keys[i].keyType, keys[i].key, keys[i].key, 0, new bytes(0));
        }
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

        // NOTED: Commented out event to handle it for migration, add back in?
        // emit Add(rid, keyType, key, key, metadataType, metadata);

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