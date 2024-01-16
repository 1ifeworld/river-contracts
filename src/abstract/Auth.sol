// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "../IdRegistry.sol";
import {DelegateRegistry} from "../DelegateRegistry.sol";

/**
 * @title Auth
 * @author Lifeworld
 */
abstract contract Auth {
    error Unauthorized_Signer_For_User(uint256 userId);

    function _authorizationCheck(
        IdRegistry idRegistry,
        DelegateRegistry delegateRegistry,
        address account,
        uint256 userId
    ) internal view returns (address) {
        // Check that sender has write access for userId
        if (account != idRegistry.custodyOf(userId) && account != delegateRegistry.delegateOf(userId)) {
            revert Unauthorized_Signer_For_User(userId);
        }
        // Return account address as authorized sender
        return account;
    }
}
