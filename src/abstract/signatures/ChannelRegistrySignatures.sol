// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Signatures} from "./Signatures.sol";
import {EIP712} from "../EIP712.sol";

abstract contract ChannelRegistrySignatures is Signatures, EIP712 {
    
    //////////////////////////////////////////////////
    // ITEM REGISTRY HELPERS
    ////////////////////////////////////////////////// 

    /*
        NOTE: 
        Constant values for function specific typehashes can be found in
        ChannelRegistry.sol
    */
    
    // function _verifyNewItemsSig(         
    //     uint256 userId, 
    //     IItemRegistry.NewItem[] memory newItemInputs, 
    //     address signer,
    //     bytes32 typehash,
    //     uint256 deadline, 
    //     bytes memory sig
    // ) internal view {
    //     _verifySig(
    //         _hashTypedDataV4(keccak256(abi.encode(typehash, userId, newItemInputs, deadline))),
    //         signer,
    //         deadline,
    //         sig
    //     );
    // }          
}