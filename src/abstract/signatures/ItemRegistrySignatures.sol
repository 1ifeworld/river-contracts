// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IItemRegistry} from "../../interfaces/IItemRegistry.sol";
import {Signatures} from "./Signatures.sol";
import {EIP712} from "../EIP712.sol";


abstract contract ItemRegistrySignatures is Signatures, EIP712 {
    
    //////////////////////////////////////////////////
    // ITEM REGISTRY HELPERS
    ////////////////////////////////////////////////// 

    /*
        NOTE: 
        Constant values for function specific typehashes can be found in
        ItemRegistry.sol
    */
    
    function _verifyNewItemsSig(         
        uint256 userId, 
        IItemRegistry.NewItem[] memory newItemInputs, 
        address signer,
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, newItemInputs, deadline))),
            signer,
            deadline,
            sig
        );
    }          

    function _verifyAddSig(        
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash,
        address signer, 
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, itemHash, channelHash, deadline))),
            signer,
            deadline,
            sig
        );
    }  

    function _verifyAddBatchSig(
        
        uint256 userId, 
        bytes32 itemHash,
        bytes32[] calldata channelHashes,
        address signer, 
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, itemHash, channelHashes, deadline))),
            signer,
            deadline,
            sig
        );
    }             

    function _verifyRemoveSig(
        
        uint256 userId, 
        bytes32 itemHash,
        bytes32 channelHash,
        address signer, 
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, itemHash, channelHash, deadline))),
            signer,
            deadline,
            sig
        );
    }      

    function _verifyEditSig(
        
        uint256 userId, 
        bytes32 itemHash,
        bytes calldata data,
        address signer, 
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, itemHash, data, deadline))),
            signer,
            deadline,
            sig
        );
    }     

    function _verifyUpdateAdminsSig(
        uint256 userId, 
        bytes32 itemHash,
        uint256[] memory userIds,
        bool[] memory stauses,
        address signer, 
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(
                typehash, 
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