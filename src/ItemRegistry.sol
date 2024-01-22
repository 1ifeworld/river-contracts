// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ChannelRegistry} from "./ChannelRegistry.sol";
import {IItemRegistry} from "./interfaces/IItemRegistry.sol";
import {IRoles} from "./interfaces/IRoles.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";
import {Auth} from "./abstract/Auth.sol";
import {Hash} from "./abstract/Hash.sol";
import {Salt} from "./abstract/Salt.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {ItemRegistrySignatures} from "./abstract/signatures/ItemRegistrySignatures.sol";
// import {Nonces} from "./abstract/Nonces.sol";

/*
    TODO:
    BETTER UNDERSTAND IF NEED TO ADD NONCE CHECKS
    BACK INTO SIGNATURE FUNCTIONS. ESP FOR UPDATE ADMINS?
*/

/**
 * @title ItemRegistry
 * @author Lifeworld
 */
contract ItemRegistry is IItemRegistry, IRoles, ItemRegistrySignatures, Auth, Hash, Salt {
    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////

    enum Actions {
        ADD,
        REMOVE
    }

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    error No_Add_Access();
    error No_Remove_Access();
    error No_Edit_Access();
    error Input_Length_Mismatch();
    error Only_Admin();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    // event New(address sender, uint256 userId, bytes32[] itemHashes, address[] pointers);
    event New(address sender, uint256 userId, bytes32 itemHashe, address pointer);
    event Add(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);
    event Remove(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);
    event Edit(address sender, uint256 userId, bytes32 itemHash, address pointer);
    event UpdateAdmins(address sender, uint256 userId, bytes32 itemHash, uint256[] userIds, bool[] statuses);

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////

    bytes32 public constant NEW_ITEMS_TYPEHASH = keccak256("NewItems(uint256 userId,Init[] inits,uint256 deadline)");

    bytes32 public constant ADD_TYPEHASH =
        keccak256("Add(uint256 userId,bytes32 itemHash,bytes32 channelHash,uint256 deadline)");

    bytes32 public constant ADD_BATCH_TYPEHASH =
        keccak256("Add(uint256 userId,bytes32 itemHash,bytes32[] channelHashes,uint256 deadline)");

    bytes32 public constant REMOVE_TYPEHASH =
        keccak256("Remove(uint256 userId,bytes32 itemHash,bytes32 channelHash,uint256 deadline)");

    bytes32 public constant EDIT_TYPEHASH =
        keccak256("Edit(uint256 userId,bytes32 itemHash,bytes data,uint256 deadline)");

    bytes32 public constant UPDATE_ADMINS_TYPEHASH =
        keccak256("UpdateAdmins(uint256 userId,bytes32 itemHash,uint256[] userIds,bool[] statuses,uint256 deadline)");

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    address public immutable self;
    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;
    ChannelRegistry public channelRegistry;
    mapping(uint256 userId => uint256 itemCount) public itemCountForUser;
    mapping(bytes32 itemHash => address pointer) public dataForItem;
    mapping(bytes32 itemHash => mapping(uint256 userId => bool status)) public isAdminForItem;
    mapping(bytes32 itemHash => mapping(bytes32 channelHash => uint256 userId)) public addedItemToChannel;

    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////

    constructor(address _idRegistry, address _delegateRegistry, address _channelRegistry) EIP712("ItemRegistry", "1") {
        self = address(this);
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
        channelRegistry = ChannelRegistry(_channelRegistry);
    }

    //////////////////////////////////////////////////
    // DIRECT WRITES
    //////////////////////////////////////////////////

    // rename "newItems" to "create"?
    // TODO: batch remove funciton?
    // TODO: batch edit function?
    // TODO: batch update admins function?
    // TODO: make function(s) external for gas?

    // NOTE: consider adding arbitrary data field to inits to enable signature based access control for channels
    function newItems(uint256 userId, Init[] memory inits)
        public
        returns (bytes32[] memory itemHashes, address[] memory pointers)
    {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.newItems.selector);
        // Create new items
        (itemHashes, pointers) = _unsafeNewItems(sender, userId, inits);
    }

    // NOTE: consider adding arbitrary data field here to enable signature based access control
    // Adds existing item to an existing channel
    function add(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.add.selector);
        // Check user for add access + process add
        _unsafeAdd(sender, userId, itemHash, channelHash);
    }

    // NOTE: consider adding arbitrary data field here to enable signature based access control
    // Adds existing item to an existing channel
    function addBatch(uint256 userId, bytes32 itemHash, bytes32[] calldata channelHashes) public {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.addBatch.selector);
        // Check user for add access + process add
        for (uint256 i; i < channelHashes.length; ++i) {
            _unsafeAdd(sender, userId, itemHash, channelHashes[i]);
        }
    }

    function remove(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.remove.selector);
        // Check user for remove access + process remove
        _unsafeRemove(sender, userId, itemHash, channelHash);
    }

    // Passing in bytes(0) for data effectively "deletes" the contents of the item
    function edit(uint256 userId, bytes32 itemHash, bytes calldata data) public returns (address pointer) {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.edit.selector);
        // Check user for edit access + process edit
        pointer = _unsafeEdit(sender, userId, itemHash, data);
    }

    function updateAdmins(uint256 userId, bytes32 itemHash, uint256[] memory userIds, bool[] memory statuses) public {
        // Check authorization status for msg.sender      
        address sender = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, msg.sender, self, this.updateAdmins.selector);
        // Check user for updateAdmins access + process updateAdmins
        _unsafeUpdateAdmins(sender, userId, itemHash, userIds, statuses);
    }

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////

    // NOTE: consider adding arbitrary data field to inits to enable signature based access control for channels
    function newItemsFor(address signer, uint256 userId, Init[] memory inits, uint256 deadline, bytes calldata sig)
        public
        returns (bytes32[] memory itemHashes, address[] memory pointers)
    {
        // Verify valid transaction being generated on behalf of signer
        _verifyNewItemsSig(userId, inits, signer, NEW_ITEMS_TYPEHASH, deadline, sig);
        // Check authorization status for signer    
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.newItems.selector);
        // Create new items
        (itemHashes, pointers) = _unsafeNewItems(authorizedSigner, userId, inits);
    }

    function addFor(
        address signer,
        uint256 userId,
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline,
        bytes calldata sig
    ) public {
        // Verify valid transaction being generated on behalf of signer
        _verifyAddSig(userId, itemHash, channelHash, signer, ADD_TYPEHASH, deadline, sig);
        // Check authorization status for signer     
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.add.selector);
        // Check user for add access + process add
        _unsafeAdd(authorizedSigner, userId, itemHash, channelHash);
    }

    function addBatchFor(
        address signer,
        uint256 userId,
        bytes32 itemHash,
        bytes32[] calldata channelHashes,
        uint256 deadline,
        bytes calldata sig
    ) public {
        // Verify valid transaction being generated on behalf of signer
        _verifyAddBatchSig(userId, itemHash, channelHashes, signer, ADD_BATCH_TYPEHASH, deadline, sig);
        // Check authorization status for signer    
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.addBatch.selector);
        // Check user for add access + process add
        for (uint256 i; i < channelHashes.length; ++i) {
            _unsafeAdd(authorizedSigner, userId, itemHash, channelHashes[i]);
        }
    }

    function removeFor(
        address signer,
        uint256 userId,
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline,
        bytes calldata sig
    ) public {
        // Verify valid transaction being generated on behalf of signer
        _verifyRemoveSig(userId, itemHash, channelHash, signer, REMOVE_TYPEHASH, deadline, sig);
        // Check authorization status for signer     
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.remove.selector);
        // Check user for remove access + process remove
        _unsafeRemove(authorizedSigner, userId, itemHash, channelHash);
    }

    // Passing in bytes(0) for data effectively "deletes" the contents of the item
    function editFor(
        address signer,
        uint256 userId,
        bytes32 itemHash,
        bytes calldata data,
        uint256 deadline,
        bytes calldata sig
    ) external returns (address pointer) {
        // Verify valid transaction being generated on behalf of signer
        _verifyEditSig(userId, itemHash, data, signer, EDIT_TYPEHASH, deadline, sig);
        // Check authorization status for signer    
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.edit.selector);
        // Check user for edit access + process edit
        pointer = _unsafeEdit(authorizedSigner, userId, itemHash, data);
    }

    function updateAdminsFor(
        address signer,
        uint256 userId,
        bytes32 itemHash,
        uint256[] memory userIds,
        bool[] memory statuses,
        uint256 deadline,
        bytes calldata sig
    ) public {
        // Verify valid transaction being generated on behalf of signer
        _verifyUpdateAdminsSig(userId, itemHash, userIds, statuses, signer, UPDATE_ADMINS_TYPEHASH, deadline, sig);
        // Check authorization status for signer     
        address authorizedSigner = 
            _authorizationCheck(idRegistry, delegateRegistry, userId, signer, self, this.updateAdmins.selector);
        // Check user for updateAdmins access + process updateAdmins
        _unsafeUpdateAdmins(authorizedSigner, userId, itemHash, userIds, statuses);
    }

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    function itemUri(bytes32 itemHash) public view returns (string memory uri) {
        bytes memory encodedBytes = SSTORE2.read(dataForItem[itemHash]);
        address renderer = BytesLib.toAddress(encodedBytes, 0);
        bytes memory data = BytesLib.slice(encodedBytes, 20, (encodedBytes.length - 20));
        uri = IRenderer(renderer).render(data);
    }

    function generateItemHash(uint256 userId, uint256 itemId) external pure returns (bytes32 itemHash) {
        itemHash = _generateHash(userId, itemId, ITEM_SALT);
    }

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////

    function _unsafeNewItems(address sender, uint256 userId, Init[] memory inits)
        internal
        returns (bytes32[] memory itemHashes, address[] memory pointers)
    {
        // Setup memory arrays to return
        itemHashes = new bytes32[](inits.length);
        pointers = new address[](inits.length);
        // Set for loop
        for (uint256 i; i < inits.length; ++i) {
            // Increment user item count + generate itemhash
            itemHashes[i] = _generateHash(userId, ++itemCountForUser[userId], ITEM_SALT);
            // Store item data
            pointers[i] = dataForItem[itemHashes[i]] = SSTORE2.write(inits[i].data);
            // Set item admin
            isAdminForItem[itemHashes[i]][userId] = true;
            // Emit `new` data for indexing
            emit New(sender, userId, itemHashes[i], pointers[i]);
            // Check for user add access + process add to channel(s)
            for (uint256 j; j < inits[i].channels.length; ++j) {
                _unsafeAdd(sender, userId, itemHashes[i], inits[i].channels[j]);
            }
        }
    }

    function _unsafeAdd(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash) internal {
        if (channelRegistry.getAccess(userId, channelHash, uint256(Actions.ADD)) < uint256(Roles.MEMBER)) {
            revert No_Add_Access();
        }
        addedItemToChannel[itemHash][channelHash] = userId;
        emit Add(sender, userId, itemHash, channelHash);
    }

    function _unsafeRemove(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash) internal {
        if (userId != addedItemToChannel[itemHash][channelHash]) {
            if (channelRegistry.getAccess(userId, channelHash, uint256(Actions.REMOVE)) < uint256(Roles.ADMIN)) {
                revert No_Remove_Access();
            }
        }
        delete addedItemToChannel[itemHash][channelHash];
        emit Remove(sender, userId, itemHash, channelHash);
    }

    // item specific
    function _unsafeEdit(address sender, uint256 userId, bytes32 itemHash, bytes calldata data)
        internal
        returns (address pointer)
    {
        if (!isAdminForItem[itemHash][userId]) revert No_Edit_Access();
        pointer = dataForItem[itemHash] = SSTORE2.write(data);
        emit Edit(sender, userId, itemHash, pointer);
    }

    // item specific access control
    function _unsafeUpdateAdmins(
        address sender,
        uint256 userId,
        bytes32 itemHash,
        uint256[] memory userIds,
        bool[] memory statuses
    ) internal {
        // Check for valid inputs
        if (userIds.length != statuses.length) revert Input_Length_Mismatch();
        // Check if userId is admin
        if (!isAdminForItem[itemHash][userId]) revert Only_Admin();
        // Update admin statuses for specified userIds
        for (uint256 i; i < userIds.length; ++i) {
            isAdminForItem[itemHash][userIds[i]] = statuses[i];
        }
        // Emit for indexing
        emit UpdateAdmins(sender, userId, itemHash, userIds, statuses);
    }
}
