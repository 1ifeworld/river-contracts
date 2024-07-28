// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Ownable} from "@openzeppelin/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/access/Ownable2Step.sol";

abstract contract Trust is Ownable2Step {

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                     ERRORS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */    

    /// @dev Revert on array length mismatch
    error Input_Length_Mismatch();

    /// @dev Revert when an unauthorized caller calls a trusted function.
    error Only_Trusted();

    /// @dev Revert when zero address is provided as input.
    error Cannot_Set_Zero_Address();

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                     EVENTS                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    /**
     * @dev Emit an event when a trusted caller is modified.
     *
     * @param account   The address of target account
     * @param status    The status of target account
     * @param owner     The address of the owner setting the new caller.
     */
    event SetTrusted(address indexed account, bool indexed status, address owner);

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                    STORAGE                     *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    /**
     * @dev Tracks what addresses are allowed to call `trusted` functions
     */
    mapping(address => bool) public isTrusted;

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                   MODIFIERS                    *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  


    /**
     * @dev Allow only the trusted caller to call the modified function.
     */
    modifier onlyTrusted() {
        if (msg.sender != owner() && !isTrusted[msg.sender]) {
            revert Only_Trusted();
        }
        _;
    }
    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                  CONSTRUCTOR                   *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    /**
     * @param _initialOwner Initial contract owner address.
     */
    constructor(address _initialOwner) Ownable(_initialOwner) {}

    /* * * * * * * * * * * * * * * * * * * * * * * * *
    *                                                *
    *                                                *
    *                  SET TRUSTED                   *
    *                                                *
    *                                                *
    * * * * * * * * * * * * * * * * * * * * * * * * */  

    /**
     * @notice Change trusted accounts by calling this from the contract's owner.
     *
     * @param accounts Accounts to update trusted status
     * @param statuses Status values to update accounts with
     */
    function setTrusted(address[] memory accounts, bool[] memory statuses) public onlyOwner {
        _setTrusted(msg.sender, accounts, statuses);
    }

    /**
     * @dev Internal helper to update `isTrusted` values
     */
    function _setTrusted(address _sender, address[] memory _accounts, bool[] memory _statuses) internal {
        if (_accounts.length != _statuses.length) revert Input_Length_Mismatch();
        for (uint256 i = 0; i < _accounts.length; ++i) {
            if (_accounts[i] == address(0)) revert Cannot_Set_Zero_Address();
            isTrusted[_accounts[i]] = _statuses[i];
            emit SetTrusted(_accounts[i], _statuses[i], _sender);
        }
    }
}