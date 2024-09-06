// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Pausable} from "@openzeppelin/utils/Pausable.sol";
import {Business} from "./abstract/Business.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Nonces} from "./abstract/Nonces.sol";
import {Signatures} from "./abstract/Signatures.sol";
import {IRiverRegistry} from "./interfaces/IRiverRegistry.sol";
import {EnumerableKeySet, KeySet} from "./libraries/EnumerableKeySet.sol";

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

    string public constant VERSION = "2024.08.01";

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

    /**
     * @notice Marks the rid after which new registrations can begin
     */
    uint256 public constant RID_MIGRATION_CUTOFF = 208;        

    /**
     * @notice Maximum number of keys that can be in ADDED state at a given time for an rid
     */
    uint256 public constant MAX_KEYS_PER_RID = 500;

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

    /**
     * @notice Last rid that was issued
     */
    uint256 public idCount;

    /**
     * @notice Maps each address to an rid, or zero if it does not own an rid.
     */
    mapping(address owner => uint256 rid) public idOf;

    /**
     * @notice Maps each rid to the address that currently owns it.
     */
    mapping(uint256 rid => address owner) public custodyOf;

    /**
     * @notice Maps each rid to an address that can initiate a recovery.
     */
    mapping(uint256 rid => address recovery) public recoveryOf;

    /**
     * @notice Maps each rid to status of whether it has been migrated.
     */
    mapping(uint256 rid => bool migrated) public hasMigrated;

    //////////////////////////////////////////////////
    // KEYS
    //////////////////////////////////////////////////  

    /**
     * @notice Maps active keys per rid
     */
    mapping(uint256 rid => KeySet activeKeys) internal _activeKeysByRid;

    /**
     * @notice Maps removed keys per rid
     */    
    mapping(uint256 rid => KeySet removedKeys) internal _removedKeysByRid;    

    /**
     * @notice Maps rid to its keys and their data
     */    
    mapping(uint256 rid => mapping(bytes key => KeyData data)) public keys;    

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                 CONSTRUCTOR                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /**
     * @dev Handles constructor calls documented in Business.sol and EIP712.sol
     */
    constructor(
        address initialOwner,
        address payoutRecipient,
        uint256 price
    ) Business(initialOwner, payoutRecipient, price) EIP712("RiverRegistry", "1") {}  

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                   MIGRATION                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */      

    /**
     * @notice Used to prep rids before migration cutoff to be migrated (batch)
     *
     * @param to        The addresses to issue rids to
     * @param recovery  Account to grant recovery abilities to
     */
    function trustedPrepMigrationBatch(address[] memory to, address recovery) public onlyTrusted {
        for (uint256 i; i < to.length; ++i) {
            // Revert if targeting an rid after migration cutoff
            if (idCount >= RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
            // Process issue without sig checks
            _issue(to[i], recovery);
        }
    }    

    /**
     * @notice Used to prep rids before migration cutoff to be migrated
     *
     * @param to        The addresses to issue rids to
     * @param recovery  Account to grant recovery abilities to
     */
    function trustedPrepMigration(address to, address recovery) public onlyTrusted {
        // Revert if targeting an rid after migration cutoff
        if (idCount >= RID_MIGRATION_CUTOFF) revert Past_Migration_Cutoff();
        // Process issue without sig checks
        _issue(to, recovery);
    }

    /**
     * @notice Used to migrate rids issues before migration cutoff
     *
     * @param rid        Target rid
     * @param recipient  Account to migrate rid custody to
     * @param recovery   Account to grant recovery abilities to
     * @param keyInits   Initial keys to add for rid
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
        // Change recovery address
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
     * @notice Used to issue new rid and add initial signing keys on behalf of msg.sender
     *
     * @param recovery   Account to grant recovery abilities to
     * @param keyInits   Initial keys to add for rid
     */
    function register(address recovery, KeyInit[] calldata keyInits) external paid payable returns (uint256 rid) {
        // Check if recipient is allowed
        _isAllowed(msg.sender);
        // Process register and add
        rid = _register(msg.sender, recovery, keyInits);
        // Decrease allowance if contract still !isPublic
        if (!isPublic) _unsafeDecreaseAllowance(msg.sender);
    }

    /**
     * @notice Used to issue new rid and add initial signing keys on behalf of an account
     *
     * @param recipient  Account to migrate rid custody to
     * @param recovery   Account to grant recovery abilities to
     * @param keyInits   Initial keys to add for rid
     * @param deadline   Expiration timestamp of the signature.
     * @param sig        EIP-712 Transfer signature signed by the recipient address.
     */
    function registerFor(address recipient, address recovery, KeyInit[] calldata keyInits, uint256 deadline, bytes calldata sig) external paid payable returns (uint256 rid) {        
        // Revert if signature invalid
        _verifyRegisterSig(recipient, recovery, keyInits, deadline, sig);
        // Check if recipient is allowed
        _isAllowed(recipient);        
        // Process register and add
        rid = _register(recipient, recovery, keyInits);
        // Decrease recipient allowance if contract still set to !isPublic
        if (!isPublic) _unsafeDecreaseAllowance(recipient);           
    }

    /**
     * @notice Used to issue new rid and add initial signing keys for any account.
     *
     * @dev Only callable by trusted caller
     * @dev Bypasses allowance checks + decreases
     * @dev Bypasses payment checks + spends
     *
     * @param recovery   Account to grant recovery abilities to
     * @param keyInits   Initial keys to add for rid
     *
     */     
    function trustedRegisterFor(address recipient, address recovery, KeyInit[] calldata keyInits) external onlyTrusted returns (uint256 rid) {
        rid = _register(recipient, recovery, keyInits);
    }

    /**
     * @notice Ensures migration cutoff has been reached, then processes rid issuance + key adding
     */
    function _register(address _recipient, address _recovery, KeyInit[] calldata _keyInits) internal returns (uint256 rid) {
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
     * @notice Handles key issuance
     */ 
    function _issue(address to, address recovery) internal returns (uint256 rid) {
        rid = _unsafeIssue(to, recovery);
        emit Issue(to, idCount, recovery);
    }

    /**
     * @notice Updates necessary values during key issuance and checks if target already has rid
     * @dev No checks on who can call, enforce elsewhere
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

   /**
     * @notice Transfers an rid to another address
     *
     * @param to The address to transfer the rid to
     * @param deadline Expiration timestamp of the signature
     * @param toSig EIP-712 Transfer signature signed by the recipient address
     */
    function transfer(address to, uint256 deadline, bytes calldata toSig) external {
        uint256 fromId = _validateTransfer(msg.sender, to);

        // Revert if signature is invalid
        _verifyTransferSig({rid: fromId, to: to, deadline: deadline, signer: to, sig: toSig});

        _unsafeTransfer(fromId, msg.sender, to);
    }

    /**
     * @notice Transfers an rid on behalf of the sender and recipient
     *
     * @param from The address transferring the rid
     * @param to The address to transfer the rid to
     * @param fromDeadline Expiration timestamp of the sender's signature
     * @param fromSig EIP-712 Transfer signature signed by the sender address
     * @param toDeadline Expiration timestamp of the recipient's signature
     * @param toSig EIP-712 Transfer signature signed by the recipient address
     */
    function transferFor(
        address from,
        address to,
        uint256 fromDeadline,
        bytes calldata fromSig,
        uint256 toDeadline,
        bytes calldata toSig
    ) external {
        uint256 fromId = _validateTransfer(from, to);

        // Revert if either signature is invalid
        _verifyTransferSig({rid: fromId, to: to, deadline: fromDeadline, signer: from, sig: fromSig});
        _verifyTransferSig({rid: fromId, to: to, deadline: toDeadline, signer: to, sig: toSig});   

        _unsafeTransfer(fromId, from, to);
    }

    /**
     * @notice Transfers an rid and changes the recovery address
     *
     * @param to The address to transfer the rid to
     * @param recovery The new recovery address
     * @param deadline Expiration timestamp of the signature
     * @param sig EIP-712 Transfer and change recovery signature signed by the recipient address
     */
    function transferAndChangeRecovery(address to, address recovery, uint256 deadline, bytes calldata sig) external {
        uint256 fromId = _validateTransfer(msg.sender, to);

        // Revert if signature is invalid
        _verifyTransferAndChangeRecoverySig({
            rid: fromId,
            to: to,
            recovery: recovery,
            deadline: deadline,
            signer: to,
            sig: sig
        });

        _unsafeTransfer(fromId, msg.sender, to);
        _unsafeChangeRecovery(fromId, recovery);
    }

    /**
     * @notice Transfers an rid and changes the recovery address on behalf of the sender and recipient
     *
     * @param from The address transferring the rid
     * @param to The address to transfer the rid to
     * @param recovery The new recovery address
     * @param fromDeadline Expiration timestamp of the from signature
     * @param fromSig EIP-712 Transfer and change recovery signature signed by the sender address
     * @param toDeadline Expiration timestamp of the recipient's signature
     * @param toSig EIP-712 Transfer and change recovery signature signed by the recipient address
     */
    function transferAndChangeRecoveryFor(
        address from,
        address to,
        address recovery,
        uint256 fromDeadline,
        bytes calldata fromSig,
        uint256 toDeadline,
        bytes calldata toSig
    ) external {
        uint256 fromId = _validateTransfer(from, to);

        // Revert if either signature is invalid */
        _verifyTransferAndChangeRecoverySig({
            rid: fromId,
            to: to,
            recovery: recovery,
            deadline: fromDeadline,
            signer: from,
            sig: fromSig
        });
        _verifyTransferAndChangeRecoverySig({
            rid: fromId,
            to: to,
            recovery: recovery,
            deadline: toDeadline,
            signer: to,
            sig: toSig
        });

        _unsafeTransfer(fromId, from, to);
        _unsafeChangeRecovery(fromId, recovery);
    }    

    /**
     * @dev Retrieve rid and validate from/to
     */
    function _validateTransfer(address from, address to) internal view returns (uint256 fromId) {
        fromId = idOf[from];

        // Revert if the sender has no id
        if (fromId == 0) revert Has_No_Id();
        // Revert if recipient has an id
        if (idOf[to] != 0) revert Has_Id();
    }

    /**
     * @dev Transfer an rid to another address without checking invariants.
     * @dev Will revert if contract is paused     
     */
    function _unsafeTransfer(uint256 id, address from, address to) internal whenNotPaused {
        idOf[to] = id;
        custodyOf[id] = to;
        delete idOf[from];

        emit Transfer(from, to, id);
    }

    //////////////////////////////////////////////////
    // CHANGE RECOVERY
    //////////////////////////////////////////////////      

    /**
     * @notice Changes the recovery address for the caller's rid
     *
     * @param recovery The new recovery address
     */
    function changeRecoveryAddress(address recovery) external {
        // Revert if the caller does not own an rid
        uint256 ownerId = idOf[msg.sender];
        if (ownerId == 0) revert Has_No_Id();

        _unsafeChangeRecovery(ownerId, recovery);
    }

    /**
     * @notice Changes the recovery address on behalf of rid custody address
     *
     * @param owner Custody address of rid
     * @param recovery The new recovery address
     * @param deadline Expiration timestamp of the signature
     * @param sig EIP-712 Change recovery address signature signed by rid custody address
     */
    function changeRecoveryAddressFor(
        address owner,
        address recovery,
        uint256 deadline,
        bytes calldata sig
    ) external {
        // Revert if the caller does not own an rid
        uint256 ownerId = idOf[owner];
        if (ownerId == 0) revert Has_No_Id();

        _verifyChangeRecoveryAddressSig({
            rid: ownerId,
            from: recoveryOf[ownerId],
            to: recovery,
            deadline: deadline,
            signer: owner,
            sig: sig
        });

        _unsafeChangeRecovery(ownerId, recovery);
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

    //////////////////////////////////////////////////
    // RECOVER
    //////////////////////////////////////////////////             

    /**
     * @notice Recovers the rid on behalf of the recovery address
     *
     * @param from The address currently owning the rid
     * @param to The address to transfer the rid to
     * @param deadline Expiration timestamp of the signature
     * @param sig EIP-712 Transfer signature signed by the recipient address
     */
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
        // Reverts if contract is paused
        _unsafeTransfer(fromId, from, to);
    }

    /**
     * @notice Recovers the rid on behalf of the recovery address and recipient
     *
     * @param from The address currently owning the rid
     * @param to The address to transfer the rid to
     * @param recoveryDeadline Expiration timestamp of the recovery signature
     * @param recoverySig EIP-712 Transfer signature signed by the recovery address
     * @param toDeadline Expiration timestamp of the recipient's signature
     * @param toSig EIP-712 Transfer signature signed by the recipient address
     */
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
        // First sig enforces check on recovery account origin
        _verifyTransferSig({
            rid: fromId,
            to: to,
            deadline: recoveryDeadline,
            signer: recoveryOf[fromId],
            sig: recoverySig
        });
        _verifyTransferSig({rid: fromId, to: to, deadline: toDeadline, signer: to, sig: toSig});

        emit Recover(from, to, fromId);
        // Reverts if contract is paused
        _unsafeTransfer(fromId, from, to);
    }

    ////////////////////////////////////////////////////////////////
    // ADD KEY
    ////////////////////////////////////////////////////////////////   

    /**
     * @notice Adds a new key for the a given rid
     * @dev Only callable by trusted caller
     *
     * @param keyType The type of the key to add
     * @param key The key data to add
     */
    function trustedAddFor(
        address ridOwner,
        uint32 keyType,
        bytes calldata key
    ) external onlyTrusted {
        _add(_ridOf(ridOwner), keyType, key);
    }   

    /**
     * @notice Adds a new key for the caller's rid
     *
     * @param keyType The type of the key to add
     * @param key The key data to add
     */
    function add(
        uint32 keyType,
        bytes calldata key
    ) external {
        _add(_ridOf(msg.sender), keyType, key);
    }

   /**
     * @notice Adds a new key for the for an rid on behalf of its custody address
     *
     * @param ridOwner The address owning the rid
     * @param keyType The type of the key to add
     * @param key The key data to add
     * @param deadline Expiration timestamp of the signature
     * @param sig EIP-712 Add key signature signed by the rid custody address
     */
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
     * @notice Processes checks and storage updates when adding keys
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
     * @notice Wrapper around functionality provided by EnumerableKeySet.sol
     */    
    function _addToKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].add(key);
    }

    //////////////////////////////////////////////////
    // REMOVE KEY
    //////////////////////////////////////////////////            

    /**
     * @notice Removes a key for the caller's rid
     *
     * @param key The key data to remove
     */
    function remove(bytes calldata key) external {
        _remove(_ridOf(msg.sender), key);
    }    

    /**
     * @notice Removes a key for the specified rid owner
     *
     * @param ridOwner The address owning the rid
     * @param key The key data to remove
     * @param deadline Expiration timestamp of the signature
     * @param sig EIP-712 Remove key signature signed by the rid owner
     */
    function removeFor(
        address ridOwner,
        bytes calldata key,
        uint256 deadline,
        bytes calldata sig
    ) external  {
        _verifyRemoveSig(ridOwner, key, deadline, sig);
        _remove(_ridOf(ridOwner), key);
    }    

    /**
     * @notice Processes checks and storage updates when removing keys
     */
    function _remove(uint256 rid, bytes calldata key) internal whenNotPaused {
        KeyData storage keyData = keys[rid][key];
        if (keyData.state != KeyState.ADDED) revert Invalid_Key_State();

        _removeFromKeySet(rid, key);
        keyData.state = KeyState.REMOVED;
        emit Remove(rid, key, key);
    }   

    /**
     * @notice Wrapper around functionality provided by EnumerableKeySet.sol
     */   
    function _removeFromKeySet(uint256 rid, bytes calldata key) internal virtual {
        _activeKeysByRid[rid].remove(key);
        _removedKeysByRid[rid].add(key);
    }
                            
    ////////////////////////////////////////////////////////////////
    // VIEWS
    ////////////////////////////////////////////////////////////////   

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

    /**
     * @notice Freezes all id + key state updates in contract
     */   
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unfreezes all id + key state updates in contract
     */   
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

    function verifyRidSignature(
        address custodyAddress,
        uint256 rid,
        bytes32 digest,
        bytes calldata sig
    ) external returns (bool isValid) {
        _verifySig(digest, custodyAddress, sig);
        isValid = idOf[custodyAddress] == rid;
    }      

    function _verifyRegisterSig(address signer, address recovery, KeyInit[] calldata keyInits, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(REGISTER_TYPEHASH, signer, recovery, keyInits, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }        

    function _verifyTransferSig(uint256 rid, address to, uint256 deadline, address signer, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(TRANSFER_TYPEHASH, rid, to, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }        

    function _verifyTransferAndChangeRecoverySig(
        uint256 rid,
        address to,
        address recovery,
        uint256 deadline,
        address signer,
        bytes memory sig
    ) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(
                keccak256(
                    abi.encode(TRANSFER_AND_CHANGE_RECOVERY_TYPEHASH, rid, to, recovery, _useNonce(signer), deadline)
                )
            ),
            signer,
            deadline,
            sig
        );
    }    

    function _verifyChangeRecoveryAddressSig(
        uint256 rid,
        address from,
        address to,
        uint256 deadline,
        address signer,
        bytes memory sig
    ) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(
                keccak256(
                    abi.encode(CHANGE_RECOVERY_ADDRESS_TYPEHASH, rid, from, to, _useNonce(signer), deadline)
                )
            ),
            signer,
            deadline,
            sig
        );
    }    

    function _verifyAddSig(address signer, uint32 keyType, bytes calldata key, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(ADD_TYPEHASH, signer, keyType, key, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }     

    function _verifyRemoveSig(address signer, bytes calldata key, uint256 deadline, bytes memory sig) internal {
        _verifySigWithDeadline(
            _hashTypedDataV4(keccak256(abi.encode(REMOVE_TYPEHASH, signer, key, _useNonce(signer), deadline))),
            signer,
            deadline,
            sig
        );
    }         
}