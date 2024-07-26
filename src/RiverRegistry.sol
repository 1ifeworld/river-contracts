// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Pausable} from "@openzeppelin/utils/Pausable.sol";
import {IRiverRegistry} from "./interfaces/IRiverRegistry.sol";
import {EnumerableKeySet, KeySet} from "./libraries/EnumerableKeySet.sol";
import {Business} from "./abstract/Business.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {Signatures} from "./abstract/Signatures.sol";

/**
 * @title RiverRegistry
 *
 * @author Lifeworld
 *
 * @custom:security-contact devops@lifeworld.co
 */
contract RiverRegistry is IRiverRegistry, Business, Pausable, Nonces, Signatures, EIP712 {
    using EnumerableKeySet for KeySet;

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                  CONSTANTS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    string public constant NAME = "RiverRegistry";

    string public constant VERSION = "2024.08.22";

    bytes32 public constant REGISTER_TYPEHASH = 
        keccak256("Register(address to,address recovery,KeyData[] keys,uint256 nonce,uint256 deadline)");  

    bytes32 public constant TRANSFER_TYPEHASH =
        keccak256("Transfer(uint256 rid,address to,uint256 nonce,uint256 deadline)");        

    bytes32 public constant TRANSFER_AND_CHANGE_RECOVERY_TYPEHASH =
        keccak256("TransferAndChangeRecovery(uint256 rid,address to,address recovery,uint256 nonce,uint256 deadline)");

    bytes32 public constant CHANGE_RECOVERY_ADDRESS_TYPEHASH =
        keccak256("ChangeRecoveryAddress(uint256 rid,address from,address to,uint256 nonce,uint256 deadline)");        

    bytes32 public constant ADD_TYPEHASH =
        keccak256("Remove(address owner,uint32 keyType,bytes key,uint256 nonce,uint256 deadline)");

    bytes32 public constant REMOVE_TYPEHASH =
        keccak256("Remove(address owner,bytes key,uint256 nonce,uint256 deadline)");        

    uint256 public constant MAX_KEYS_PER_RID = 500;

    uint256 public constant RID_MIGRATION_CUTOFF = 200;

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                   STORAGE                      *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */   

    //////////////////////////////////////////////////
    // IDS
    //////////////////////////////////////////////////  

    uint256 public idCount;
    mapping(address owner => uint256 rid) public idOf;
    mapping(uint256 rid => address owner) public custodyOf;
    mapping(uint256 rid => address recovery) public recoveryOf;
    mapping(uint256 rid => bool migrated) public hasMigrated;

    //////////////////////////////////////////////////
    // KEYS
    //////////////////////////////////////////////////  

    mapping(uint256 rid => KeySet activeKeys) internal _activeKeysByRid;
    mapping(uint256 rid => KeySet removedKeys) internal _removedKeysByRid;    
    mapping(uint256 rid => mapping(bytes key => KeyData data)) public keys;    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 CONSTRUCTOR                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /**
     * @dev fill in
     */
    constructor(
        address initialOwner,
        address[] memory initialTrustedCallers,
        address payoutRecipient,
        uint256 price
    ) Business(initialOwner, payoutRecipient, price) EIP712("RiverRegistry", "1") {
        bool[] memory trues = new bool[](initialTrustedCallers.length);
        for (uint256 i; i < initialTrustedCallers.length; ++i) {
            trues[i] = true;
        }
        _setTrusted(initialTrustedCallers, trues);
    }  

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                   MIGRATION                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /**
     * @dev fill in
     */
    function trustedPrepMigration(address to, address recovery) public onlyTrusted {
        // Revert if targeting an rid after migration cutoff
        if (idCount >= RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Process issue without sig checks
        _issue(to, recovery);
    }

    /**
     * @dev fill in
     */
    function trustedMigrateFor(uint256 rid, address recipient, address recovery, KeyInit[] calldata keyInits) public onlyTrusted {
        // Revert if targeting an rid after migration cutoff
        if (rid > RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Revert if rid has already migrated
        if (hasMigrated[rid]) revert Already_Migrated();        
        // Check rid has been issued, and that recipient doesnt currently own an rid
        address fromCustody = _validateMigration(rid, recipient);
        // Transfer rid
        _unsafeTransfer(rid, fromCustody, recipient);
        // Change recovery addresss
        _unsafeChangeRecovery(rid, recovery);
        // Add keys
        for (uint256 i; i < keyInits.length; ++i) {
            _add(rid, keyInits[i].keyType, keyInits[i].key);
        }
        // Update migration state for rid and emit event
        hasMigrated[rid] = true;
        emit Migrate(rid);
    }

    /**
     * @dev Retrieve custody and validate rid/recipient
     */
    function _validateMigration(uint256 rid, address to) internal whenNotPaused view returns (address fromCustody) {
        // Retrieve current custody address of target rid
        fromCustody = custodyOf[rid];
        // Revert if rid not issued
        if (fromCustody == address(0)) revert Has_No_Id();
        // Revert if recipient already has rid
        if (idOf[to] != 0) revert Has_Id();
    }    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *             ID + KEY MANAGEMENT                *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */   

    //////////////////////////////////////////////////
    // REGISTER
    //////////////////////////////////////////////////      

    /**
     * @dev fill in
     */
    function register(address recovery, KeyInit[] calldata keyInits) external paid payable returns (uint256 rid) {
        // Check if recipient is allowed
        _isAllowed(msg.sender);
        // Process register and add
        rid = _issueAndAdd(msg.sender, recovery, keyInits);
        // Decrease allowance if contract still !isPublic
        if (!isPublic) _unsafeDecreaseAllowance(msg.sender);
    }

    /**
     * @dev fill in
     */
    function registerFor(address recipient, address recovery, KeyInit[] calldata keyInits, uint256 deadline, bytes calldata sig) external paid payable returns (uint256 rid) {        
        // Revert if signature invalid
        _verifyRegisterSig(recipient, recovery, keyInits, deadline, sig);
        // Check if recipient is allowed
        _isAllowed(recipient);        
        // Process register and add
        rid = _issueAndAdd(recipient, recovery, keyInits);
        // Decrease recipient allowance if contract still set to !isPublic
        if (!isPublic) _unsafeDecreaseAllowance(recipient);           
    }

    // NOTE: add payable? without price check?
    /**
     * @dev Bypasses allowance checks + decreases
     * @dev Bypasses payment checks + spends
     */    
    function trustedRegisterFor(address recipient, address recovery, KeyInit[] calldata keyInits) external onlyTrusted returns (uint256 rid) {
        rid = _issueAndAdd(recipient, recovery, keyInits);
    }

    /**
     * @dev fill in
     */
    function _issueAndAdd(address _recipient, address _recovery, KeyInit[] calldata _keyInits) internal returns (uint256 rid) {
        // Cannot register until migration cutoff has been reached
        if (idCount < RID_MIGRATION_CUTOFF) revert Before_Migration_Cutoff();
        // Register rid
        rid = _issue(_recipient, _recovery);
        // Add keys
        for (uint256 i; i < _keyInits.length; ++i) {
            _add(rid, _keyInits[i].keyType, _keyInits[i].key);
        }             
    }
    
    /**
     * @dev fill in
     */    
    function _issue(address to, address recovery) internal returns (uint256 rid) {
        rid = _unsafeIssue(to, recovery);
        emit Issue(to, idCount, recovery);
    }

    /**
     * @dev fill in
     */
    function _unsafeIssue(address to, address recovery) internal whenNotPaused returns (uint256 rid) {
        // Revert if the target(to) has an rid 
        if (idOf[to] != 0) revert Has_Id();
        // Incrementing before assignment ensures that no one gets the 0 rid.
        rid = ++idCount;
        // Issue id
        idOf[to] = rid;
        custodyOf[rid] = to;
        recoveryOf[rid] = recovery;
    }

    //////////////////////////////////////////////////
    // TRANSFER
    //////////////////////////////////////////////////      

    /***
    
            DO THINKING ABOUT WHAT THE TRUST AND PAUSE MODELS SHOULD BE HERE
    
     */    

    function transfer(address to, uint256 deadline, bytes calldata sig) external {
        address from = msg.sender;
        uint256 fromId = idOf[from];

        // Revert if the sender has no id
        if (fromId == 0) revert Has_No_Id();
        // Revert if recipient has an id
        if (idOf[to] != 0) revert Has_Id();

        // Revert if signature is invalid
        _verifyTransferSig({rid: fromId, to: to, deadline: deadline, signer: to, sig: sig});

        _unsafeTransfer(fromId, from, to);
    }

    function transferFor(
        address from,
        address to,
        uint256 fromDeadline,
        bytes calldata fromSig,
        uint256 toDeadline,
        bytes calldata toSig
    ) external {
        uint256 fromId = idOf[from];

        // Revert if the sender has no id
        if (fromId == 0) revert Has_No_Id();
        // Revert if recipient has an id
        if (idOf[to] != 0) revert Has_Id();

        // Revert if either signature is invalid
        _verifyTransferSig({rid: fromId, to: to, deadline: fromDeadline, signer: from, sig: fromSig});
        _verifyTransferSig({rid: fromId, to: to, deadline: toDeadline, signer: to, sig: toSig});        

        _unsafeTransfer(fromId, from, to);
    }


    /**
     * @dev Retrieve rid and validate sender/recipient
     */
    function _validateTransfer(address from, address to) internal view returns (uint256 fromId) {
        fromId = idOf[from];

        // Revert if the sender has no id
        if (fromId == 0) revert Has_No_Id();
        // Revert if recipient has an id
        if (idOf[to] != 0) revert Has_Id();
    }

    /**
     * @dev Transfer the rid to another address without checking invariants.
     * @dev Will revert if contract is paused     
     */
    function _unsafeTransfer(uint256 id, address from, address to) internal whenNotPaused {
        idOf[to] = id;
        custodyOf[id] = to;
        delete idOf[from];

        emit Transfer(from, to, id);
    }

    //////////////////////////////////////////////////
    // RECOVER
    //////////////////////////////////////////////////      

    /***
    
            DO THINKING ABOUT WHAT THE TRUST AND PAUSE MODELS SHOULD BE HERE
    
     */

    function changeRecoveryAddress(address recovery) external onlyTrusted whenNotPaused {
        // Revert if the caller does not own an rid
        uint256 ownerId = idOf[msg.sender];
        if (ownerId == 0) revert Has_No_Id();

        // Change the recovery address
        recoveryOf[ownerId] = recovery;

        emit ChangeRecoveryAddress(ownerId, recovery);
    }

    function changeRecoveryAddressFor(
        address owner,
        address recovery,
        uint256 deadline,
        bytes calldata sig
    ) external whenNotPaused {
        // Revert if the caller does not own an rid
        uint256 ownerId = idOf[owner];
        if (ownerId == 0) revert Has_No_Id();

        _verifyChangeRecoverySig({rid: ownerId, recovery: recovery, deadline: deadline, signer: owner, sig: sig});

        // Change the recovery address
        recoveryOf[ownerId] = recovery;

        emit ChangeRecoveryAddress(ownerId, recovery);
    }

    function recover(address from, address to, uint256 deadline, bytes calldata sig) external {
        // Revert if from does not own an rid
        uint256 fromId = idOf[from];
        if (fromId == 0) revert Has_No_Id();

        // Revert if the caller is not the recovery address
        address caller = msg.sender;
        if (recoveryOf[fromId] != caller) revert Unauthorized();

        // Revert if destination(to) already has an rid
        if (idOf[to] != 0) revert Has_Id();

        // Revert if signature is invalid
        _verifyTransferSig({rid: fromId, to: to, deadline: deadline, signer: to, sig: sig});

        emit Recover(from, to, fromId);
        _unsafeTransfer(fromId, from, to);
    }

    function recoverFor(
        address from,
        address to,
        uint256 recoveryDeadline,
        bytes calldata recoverySig,
        uint256 toDeadline,
        bytes calldata toSig
    ) external {
        // Revert if from does not own an rid
        uint256 fromId = idOf[from];
        if (fromId == 0) revert Has_No_Id();

        // Revert if destination(to) already has an rid
        if (idOf[to] != 0) revert Has_Id();

        // Revert if either signature is invalid
        _verifyTransferSig({
            rid: fromId,
            to: to,
            deadline: recoveryDeadline,
            signer: recoveryOf[fromId],
            sig: recoverySig
        });
        _verifyTransferSig({rid: fromId, to: to, deadline: toDeadline, signer: to, sig: toSig});

        emit Recover(from, to, fromId);
        _unsafeTransfer(fromId, from, to);
    }

    /**
     * @dev Change recovery address without checking invariants.
     * @dev Will revert if contract is paused
     */
    function _unsafeChangeRecovery(uint256 id, address recovery) internal whenNotPaused {
        // Change the recovery address
        recoveryOf[id] = recovery;

        emit ChangeRecoveryAddress(id, recovery);
    }    

    ////////////////////////////////////////////////////////////////
    // ADD KEY
    ////////////////////////////////////////////////////////////////   

    /**
     * @dev No signature checks performed
     * @dev Only callable by trusted caller
     */
    function trustedAddFor(
        address ridOwner,
        uint32 keyType,
        bytes calldata key
    ) external onlyTrusted {
        _add(_ridOf(ridOwner), keyType, key);
    }   

    // No isAllowed check hear on purpose
    function add(
        uint32 keyType,
        bytes calldata key
    ) external {
        _add(_ridOf(msg.sender), keyType, key);
    }

    // No isAllowed check hear on purpose
    function addFor(
        address ridOwner,
        uint32 keyType,
        bytes calldata key,
        uint256 deadline,
        bytes calldata sig
    ) external {
        // Revert if signature invalid
        _verifyAddSig(ridOwner, keyType, key, deadline, sig);
        _add(_ridOf(ridOwner), keyType, key);
    }        

    /**
     * @dev fill in
     */
    function _add(
        uint256 rid,
        uint32 keyType,
        bytes calldata key
    ) internal whenNotPaused {
        KeyData storage keyData = keys[rid][key];
        if (keyData.state != KeyState.NULL) revert Invalid_Key_State();
        if (totalKeys(rid, KeyState.ADDED) >= MAX_KEYS_PER_RID) revert Exceeds_Maximum();

        _addToKeySet(rid, key);
        keyData.state = KeyState.ADDED;
        keyData.keyType = keyType;

        emit Add(rid, keyType, key, key);
    }                 

    /**
     * @dev fill in
     */
    function _addToKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].add(key);
    }

    //////////////////////////////////////////////////
    // REMOVE KEY
    //////////////////////////////////////////////////          

    function remove(bytes calldata key) external {
        _remove(_ridOf(msg.sender), key);
    }    

    function removeFor(
        address ridOwner,
        bytes calldata key,
        uint256 deadline,
        bytes calldata sig
    ) external  {
        _verifyRemoveSig(ridOwner, key, deadline, sig);
        _remove(_ridOf(ridOwner), key);
    }    

    function _remove(uint256 rid, bytes calldata key) internal whenNotPaused {
        KeyData storage keyData = keys[rid][key];
        if (keyData.state != KeyState.ADDED) revert Invalid_Key_State();

        _removeFromKeySet(rid, key);
        keyData.state = KeyState.REMOVED;
        emit Remove(rid, key, key);
    }   

    /**
     * @dev fill in
     */
    function _removeFromKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].remove(key);
        _removedKeysByRid[rid].add(key);
    }
                            
    ////////////////////////////////////////////////////////////////
    // VIEWS
    ////////////////////////////////////////////////////////////////   

    //      

    function verifyRidSignature(
        address custodyAddress,
        uint256 rid,
        bytes32 digest,
        bytes calldata sig
    ) external returns (bool isValid) {
        _verifySig(digest, custodyAddress, sig);
        isValid = idOf[custodyAddress] == rid;
    }

    function _ridOf(address ridOwner) internal view returns (uint256 rid) {
        rid = idOf[ridOwner];
        if (rid == 0) revert Unauthorized();
    }

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

    function _keysByState(uint256 rid, KeyState state) internal view returns (KeySet storage) {
        if (state == KeyState.ADDED) {
            return _activeKeysByRid[rid];
        } else if (state == KeyState.REMOVED) {
            return _removedKeysByRid[rid];
        } else {
            revert Invalid_Key_State();
        }
    }    
        
    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    ADMIN                       *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
    
    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *              SIGNATURE HELPERS                 *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    function _verifyRegisterSig(address owner, address recovery, KeyInit[] calldata keyInits, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(REGISTER_TYPEHASH, owner, recovery, keyInits, _useNonce(owner), deadline))),
            owner,
            deadline,
            sig
        );
    }        

    function _verifyTransferSig(uint256 rid, address signer, uint256 deadline, address to, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(TRANSFER_TYPEHASH, rid, to, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }

    function _verifyTransferAndChangeRecoverySig(
        uint256 rid,
        address owner,
        address to,
        address recovery,
        uint256 deadline,    
        bytes memory sig
    ) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(
                keccak256(
                    abi.encode(TRANSFER_AND_CHANGE_RECOVERY_TYPEHASH, rid, to, recovery, _useNonce(owner), deadline)
                )
            ),
            owner,
            deadline,
            sig
        );
    }    

    function _verifyChangeRecoverySig(uint256 rid, address signer, address recovery, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(CHANGE_RECOVERY_ADDRESS_TYPEHASH, rid, signer, recovery, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }            

    function _verifyAddSig(address owner, uint32 keyType, bytes calldata key, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(ADD_TYPEHASH, owner, keyType, key, _useNonce(owner), deadline))),
            owner,
            deadline,
            sig
        );
    }     

    function _verifyRemoveSig(address owner, bytes calldata key, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(REMOVE_TYPEHASH, owner, key, _useNonce(owner), deadline))),
            owner,
            deadline,
            sig
        );
    }         
}