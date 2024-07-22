// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Ownable2Step} from "@openzeppelin/access/Ownable2Step.sol";

abstract contract Trust2 is Ownable2Step {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Revert on array length mismatch
    error Input_Length_Mismatch();

    /// @dev Revert when an unauthorized caller calls a trusted function.
    error Only_Trusted();

    /// @dev Revert when an invalid address is provided as input.
    error Invalid_Address();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Emit an event when a trusted caller is modified.
     *
     * @param account   The address of target account
     * @param status    The status of target account
     * @param owner     The address of the owner setting the new caller.
     */
    event SetTrusted(address indexed account, bool indexed status, address owner);

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Tracks what addresses are allowed to call `trusted` functions
     */
    mapping(address => bool) public isTrusted;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/


    /**
     * @dev Allow only the trusted caller to call the modified function.
     */
    modifier onlyTrusted() {
        if (msg.sender != owner() && !isTrusted[msg.sender]) {
            revert Only_Trusted();
        }
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    // /**
    //  * @param _initialOwner Initial contract owner address.
    //  */
    // constructor(address _initialOwner) Ownable(_initialOwner) {}

    /**
     * @param _initialOwner Initial contract owner address.
     */
    constructor(address _initialOwner) {
        _transferOwnership(_initialOwner);
    }    

    /*//////////////////////////////////////////////////////////////
                         PERMISSIONED ACTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Change the trusted caller by calling this from the contract's owner.
     *
     * @param accounts Accounts to update trusted caller status
     * @param statuses Boolean values to update accounts with
     */
    function setTrusted(address[] memory accounts, bool[] memory statuses) public onlyOwner {
        _setTrusted(accounts, statuses);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Internal helper to set trusted caller. Can be used internally
     *      to set the trusted caller at construction time.
     */
    function _setTrusted(address[] memory _accounts, bool[] memory _statuses) internal {
        address sender = msg.sender;
        if (_accounts.length != _statuses.length) revert Input_Length_Mismatch();
        for (uint256 i = 0; i < _accounts.length; ++i) {
            if (_accounts[i] == address(0)) revert Invalid_Address();
            isTrustedCaller[_accounts[i]] = _statuses[i];
            emit SetTrusted(_accounts[i], _statuses[i], sender);
        }
    }
}