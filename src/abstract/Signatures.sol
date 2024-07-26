// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {SignatureCheckerLib} from "@solady/utils/SignatureCheckerLib.sol";

abstract contract Signatures {

    //////////////////////////////////////////////////
    // ERRORS
    ////////////////////////////////////////////////// 

    /// @dev Revert when the signature provided is invalid.
    error Invalid_Signature();

    /// @dev Revert when the block.timestamp is ahead of the signature deadline.
    error Signature_Expired();    
    
    //////////////////////////////////////////////////
    // GENERIC HELPERS
    ////////////////////////////////////////////////// 

    function _verifySig(bytes32 digest, address signer, bytes memory sig) internal {
        // ERC1271 sig validation for EOAs or accounts with code
        if (!SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) {
            // ERC6492 sig validation for predeploy accounts
            if (!SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) {
                revert Invalid_Signature();
            }
        }
    }

    function _verifySigWithDeadline(bytes32 digest, address signer, uint256 deadline, bytes memory sig) internal {
        if (block.timestamp > deadline) revert Signature_Expired();
        // ERC1271 sig validation for EOAs or accounts with code
        if (!SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) {
            // ERC6492 sig validation for predeploy accounts
            if (!SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) {
                revert Invalid_Signature();
            }
        }
    }        

    // function _verifySigWithDeadline(bytes32 digest, address signer, uint256 deadline, bytes memory sig) internal {
    //     if (block.timestamp > deadline) revert Signature_Expired();
    //     // ERC1271 sig validation for EOAs or accounts with code
    //     if (!SignatureChecker.isValidSignatureNow(signer, digest, sig)) {
    //         revert Invalid_Signature();
    //     }
    // }    

    function _verifySigWithReturn(bytes32 digest, address signer, bytes memory sig) internal returns (bool) {
        // ERC1271 sig validation for EOAs or accounts with code
        if (SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) return true;
        // ERC6492 sig validation for predeploy accounts
        if (SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) return true;
        // Both sig verification attempts failed. Return false
        return false;
    }        
}