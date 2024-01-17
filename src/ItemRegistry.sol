// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import "sstore2/SSTORE2.sol";
import "solidity-bytes-utils/BytesLib.sol";
import {IdRegistry} from "./IdRegistry.sol";
import {DelegateRegistry} from "./DelegateRegistry.sol";
import {ChannelRegistry} from "./ChannelRegistry.sol";
import {IRenderer} from "./interfaces/IRenderer.sol";
import {Auth} from "./abstract/Auth.sol";
import {Hash} from "./abstract/Hash.sol";
import {Salt} from "./abstract/Salt.sol";
import {EIP712} from "./abstract/EIP712.sol";
import {Signatures} from "./abstract/Signatures.sol";
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
contract ItemRegistry is Auth, Hash, Salt, EIP712, Signatures {

    //////////////////////////////////////////////////
    // TYPES
    //////////////////////////////////////////////////        

    struct NewItem {
        bytes data;
        bytes32[] channels;
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

    event New(address sender, uint256 userId, bytes32[] itemHashes, address[] pointers); 
    event Add(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);    
    event Remove(address sender, uint256 userId, bytes32 itemHash, bytes32 channelHash);
    event Edit(address sender, uint256 userId, bytes32 itemHash, address pointer); 
    event UpdateAdmins(address sender, uint256 userId, bytes32 itemHash, uint256[] userIds, bool[] statuses);

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////   
    
    bytes32 public constant NEW_ITEMS_TYPEHASH =
        keccak256("NewItems(uint256 userId,NewItem[] newItemInputs,uint256 deadline)");   

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

    IdRegistry public idRegistry;
    DelegateRegistry public delegateRegistry;    
    ChannelRegistry public channelRegistry;    
    mapping(uint256 userId => uint256 itemCount) public itemCountForUser;
    mapping(bytes32 itemHash => mapping(uint256 userId => bool status)) public isAdminForItem;
    mapping(bytes32 itemHash => address pointer) public dataForItem;
    mapping(bytes32 itemHash => mapping(bytes32 channelHash => uint256 userId)) public addedItemToChannel;
   
    //////////////////////////////////////////////////
    // CONSTRUCTOR
    //////////////////////////////////////////////////                

    constructor(address _idRegistry, address _delegateRegistry, address _channelRegistry) EIP712("ItemRegistry", "1") {
        idRegistry = IdRegistry(_idRegistry);
        delegateRegistry = DelegateRegistry(_delegateRegistry);
        channelRegistry = ChannelRegistry(_channelRegistry);
    }

    //////////////////////////////////////////////////
    // DIRECT WRITES
    //////////////////////////////////////////////////       

    // TODO: batch edit function?
    // TODO: batch remove funciton?
    // TODO: make function(s) external?
    // TODO: sort function?

    // NOTE: consider adding arbitrary data field to newItemInputs to enable signature based access control for channels
    function newItems(uint256 userId, NewItem[] memory newItemInputs) 
        public 
        returns (bytes32[] memory itemHashes, address[] memory pointers) 
    {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Create new items
        (itemHashes, pointers) = _unsafeNewItems(sender, userId, newItemInputs);
    }
     
    // NOTE: consider adding arbitrary data field here to enable signature based access control
    // Adds existing item to an existing channel
    function add(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check user for add access + process add
        _add(sender, userId, itemHash, channelHash);
    }

    // NOTE: consider adding arbitrary data field here to enable signature based access control
    // Adds existing item to an existing channel
    function addBatch(uint256 userId, bytes32 itemHash, bytes32[] calldata channelHashes) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check user for add access + process add
        for (uint256 i; i < channelHashes.length; ++i) {
            _add(sender, userId, itemHash, channelHashes[i]);
        }
    }    

    function remove(uint256 userId, bytes32 itemHash, bytes32 channelHash) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);
        // Check user for remove access + process remove
        _remove(sender, userId, itemHash, channelHash);        
    }

    // Passing in bytes(0) for data effectively "deletes" the contents of the item
    function edit(uint256 userId, bytes32 itemHash, bytes calldata data) public returns (address pointer) {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId);    
        // Check user for edit access + process edit
        pointer = _edit(sender, userId, itemHash, data);   
    }    

    function updateAdmins(uint256 userId, bytes32 itemHash, uint256[] memory userIds, bool[] memory statuses) public {
        // Check authorization status for msg.sender
        address sender = _authorizationCheck(idRegistry, delegateRegistry, msg.sender, userId); 
        // Check user for updateAdmins access + process updateAdmins
        _updateAdmins(sender, userId, itemHash, userIds, statuses);
    } 

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////          

    // NOTE: consider adding arbitrary data field to newItemInputs to enable signature based access control for channels
    function newItemsFor(
        address signer, 
        uint256 userId, 
        NewItem[] memory newItemInputs,         
        uint256 deadline, 
        bytes calldata sig
    ) public returns (bytes32[] memory itemHashes, address[] memory pointers) {
        // Verify valid transaction being generated on behalf of signer
        _verifyNewItemsSig(signer, userId, newItemInputs, deadline, sig);
        // Check authorization status for signer
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);
        // Create new items
        (itemHashes, pointers) = _unsafeNewItems(authorizedSigner, userId, newItemInputs);
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
        _verifyAddSig(signer, userId, itemHash, channelHash, deadline, sig);        
        // Check authorization status for signer
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);
        // Check user for add access + process add
        _add(authorizedSigner, userId, itemHash, channelHash);
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
        _verifyAddBatchSig(signer, userId, itemHash, channelHashes, deadline, sig);        
        // Check authorization status for signer
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);
        // Check user for add access + process add
        for (uint256 i; i < channelHashes.length; ++i) {
            _add(authorizedSigner, userId, itemHash, channelHashes[i]);
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
        _verifyRemoveSig(signer, userId, itemHash, channelHash, deadline, sig);          
        // Check authorization status for msg.sender
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);
        // Check user for remove access + process remove
        _remove(authorizedSigner, userId, itemHash, channelHash);       
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
        _verifyEditSig(signer, userId, itemHash, data, deadline, sig);         
        // Check authorization status for msg.sender
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);
        // Check user for edit access + process edit
        pointer = _edit(authorizedSigner, userId, itemHash, data);                     
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
        _verifyUpdateAdminsSig(signer, userId, itemHash, userIds, statuses, deadline, sig);
        // Check authorization status for msg.sender
        address authorizedSigner = _authorizationCheck(idRegistry, delegateRegistry, signer, userId);         
        // Check user for updateAdmins access + process updateAdmins
        _updateAdmins(authorizedSigner, userId, itemHash, userIds, statuses);
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

    function generateItemHash(uint256 userId, uint256 channelId) external pure returns (bytes32 itemHash) {
        itemHash = _generateHash(userId, channelId, ITEM_SALT);
    }     

    //////////////////////////////////////////////////
    // INTERNAL
    //////////////////////////////////////////////////  

    function _unsafeNewItems(address sender, uint256 userId, NewItem[] memory newItemInputs) 
        internal 
        returns (bytes32[] memory itemHashes, address[] memory pointers) 
    {
        // Setup memory arrays to return
        itemHashes = new bytes32[](newItemInputs.length);
        pointers = new address[](newItemInputs.length);        
        // Set for loop
        for (uint256 i; i < newItemInputs.length; ++i) {
            // Increment user item count + generate itemhash
            itemHashes[i] = _generateHash(userId, ++itemCountForUser[userId], ITEM_SALT);
            // Store item data
            pointers[i] = dataForItem[itemHashes[i]] = SSTORE2.write(newItemInputs[i].data); 
            // Set item admin     
            isAdminForItem[itemHashes[i]][userId] = true;       
            // Emit `new` data for indexing
            emit New(sender, userId, itemHashes, pointers);                                                  
            // Check for user add access + process add to channel(s)
            for (uint256 j; j < newItemInputs[i].channels.length; ++j) {
                _add(sender, userId, itemHashes[i], newItemInputs[i].channels[j]);
            }          
        }    
    }         

    function _add(
        address sender, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash
    ) internal {
        if (!channelRegistry.getAddAccess(userId, channelHash)) revert No_Add_Access();        
        addedItemToChannel[itemHash][channelHash] = userId;
        emit Add(sender, userId, itemHash, channelHash);
    }       

    function _remove(
        address sender, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash
    ) internal {
        if (userId != addedItemToChannel[itemHash][channelHash]) {
            if (channelRegistry.getRemoveAccess(userId, channelHash)) {
                revert No_Remove_Access();
            }
        }            
        delete addedItemToChannel[itemHash][channelHash];
        emit Remove(sender, userId, itemHash, channelHash);
    }        

    function _edit(
        address sender, 
        uint256 userId, 
        bytes32 itemHash,
        bytes calldata data
    ) internal returns (address pointer) {
        if (!isAdminForItem[itemHash][userId]) revert No_Edit_Access();          
        pointer = dataForItem[itemHash] = SSTORE2.write(data);
        emit Edit(sender, userId, itemHash, pointer);  
    }         

    function _updateAdmins(
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
        
    //////////////////////////////////////////////////
    // SIGNATURES
    ////////////////////////////////////////////////// 

    function _verifyNewItemsSig(
        address signer, 
        uint256 userId, 
        NewItem[] memory newItemInputs, 
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(NEW_ITEMS_TYPEHASH, userId, newItemInputs, deadline))),
            signer,
            deadline,
            sig
        );
    }          

    function _verifyAddSig(
        address signer, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(ADD_TYPEHASH, userId, itemHash, channelHash, deadline))),
            signer,
            deadline,
            sig
        );
    }  

    function _verifyAddBatchSig(
        address signer, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32[] calldata channelHashes,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(ADD_BATCH_TYPEHASH, userId, itemHash, channelHashes, deadline))),
            signer,
            deadline,
            sig
        );
    }             

    function _verifyRemoveSig(
        address signer, 
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(REMOVE_TYPEHASH, userId, itemHash, channelHash, deadline))),
            signer,
            deadline,
            sig
        );
    }      

    function _verifyEditSig(
        address signer, 
        uint256 userId, 
        bytes32 itemHash,
        bytes calldata data,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(EDIT_TYPEHASH, userId, itemHash, data, deadline))),
            signer,
            deadline,
            sig
        );
    }     

    function _verifyUpdateAdminsSig(
        address signer, 
        uint256 userId, 
        bytes32 itemHash,
        uint256[] memory userIds,
        bool[] memory stauses,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(
                UPDATE_ADMINS_TYPEHASH, 
                userId, 
                itemHash, 
                userIds, 
                stauses, 
                deadline
            ))),
            signer,
            deadline,
            sig
        );
    }       
}