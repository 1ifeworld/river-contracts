// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Nonces as NoncesBase} from "@openzeppelin/utils/Nonces.sol";

abstract contract Nonces is NoncesBase {
    //////////////////////////////////////////////////
    // NONCE MANAGEMENT
    ////////////////////////////////////////////////// 

    /**
     * @notice Increase caller's nonce, invalidating previous signatures.
     *
     * @return uint256 The caller's new nonce.
     */
    function useNonce() external returns (uint256) {
        return _useNonce(msg.sender);
    }
}