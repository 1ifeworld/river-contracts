// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Signatures} from "./Signatures.sol";
import {EIP712} from "../EIP712.sol";
import {IDelegateRegistry} from "../../interfaces/IDelegateRegistry.sol";

abstract contract DelegateRegistrySignatures is Signatures, EIP712, IDelegateRegistry {

    
    //////////////////////////////////////////////////
    // DELEGATE REGISTRY HELPERS
    ////////////////////////////////////////////////// 

    /*
        NOTE: 
        Constant values for function specific typehashes can be found in
        DelegateRegistry.sol
    */

    function _verifySetDelegatesSig(         
        uint256 userId, 
        Delegation[] memory dels,
        address signer,
        bytes32 typehash,
        uint256 deadline, 
        bytes memory sig
    ) internal view {
        _verifySig(
            _hashTypedDataV4(keccak256(abi.encode(typehash, userId, dels, deadline))),
            signer,
            deadline,
            sig
        );
    }         
}