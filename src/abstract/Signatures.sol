// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ISignatures} from "../interfaces/abstract/ISignatures.sol";

abstract contract Signatures is ISignatures {
    
    //////////////////////////////////////////////////
    // GENERIC HELPER
    ////////////////////////////////////////////////// 

    function _verifySig(bytes32 digest, address signer, bytes memory sig) internal {
        // ERC1271 sig validation for EOAs or accounts with code
        if (!SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) {
            // ERC6492 sig validation for predeploy accounts
            if (!SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) {
                revert InvalidSignature();
            }
        }
    }

    function _verifySigWithReturn(bytes32 digest, address signer, bytes memory sig) internal returns (bool) {
        // ERC1271 sig validation for EOAs or accounts with code
        if (SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) return true;
        // ERC6492 sig validation for predeploy accounts
        if (SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) return true;
        // Both sig verification attempts failed. Return false
        return false;
    }    

    function _verifySigWithDeadline(bytes32 digest, address signer, uint256 deadline, bytes memory sig) internal {
        if (block.timestamp > deadline) revert SignatureExpired();
        // ERC1271 sig validation for EOAs or accounts with code
        if (!SignatureCheckerLib.isValidSignatureNow(signer, digest, sig)) {
            // ERC6492 sig validation for predeploy accounts
            if (!SignatureCheckerLib.isValidERC6492SignatureNow(signer, digest, sig)) {
                revert InvalidSignature();
            }
        }
    }    
}