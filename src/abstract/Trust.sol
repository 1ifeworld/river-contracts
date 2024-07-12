// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Ownable2Step} from "@openzeppelin/access/Ownable2Step.sol";
import {Ownable} from "@openzeppelin/access/Ownable.sol";

abstract contract Trust is Ownable2Step {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Revert on array length mismatch
    error Input_Length_Mismatch();

    /// @dev Revert if public register is invoked before trustedCallerOnly is disabled.
    error Registratable();

    /// @dev Revert when an unauthorized caller calls a trusted function.
    error Only_Trusted();

    /// @dev Revert when an invalid address is provided as input.
    error Invalid_Address();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Emit an event when the trusted caller is modified.
     *
     * @param account   The address of target account
     * @param status    The status of target account
     * @param owner     The address of the owner setting the new caller.
     */
    event SetTrustedCaller(address indexed account, bool indexed status, address owner);

    /**
     * @dev Emit an event when the trustedOnly state is disabled.
     */
    event DisableTrustedOnly();

    /*//////////////////////////////////////////////////////////////
                              STORAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev The privileged address that is allowed to call trusted functions.
     */
    mapping(address => bool) public isTrustedCaller;

    /**
     * @dev Allows calling trusted functions when set 1, and disables trusted
     *      functions when set to 0. The value is set to 1 and can be changed to 0,
     *      but never back to 1.
     */
    uint256 public trustedOnly = 1;

    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Allow only the trusted caller to call the modified function.
     */
    modifier onlyTrustedCaller() {
        if (!isTrustedCaller[msg.sender]) revert Only_Trusted();
        _;
    }

    /**
     * @dev Allow only the trusted caller to call the modified function.
     */
    modifier whenNotTrustedOnly() {
        if(!isTrustedCaller[msg.sender]) {
            if (trustedOnly == 1) revert Registratable();
        }
        _;
    }    

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _initialOwner Initial contract owner address.
     */
    constructor(address _initialOwner) Ownable(_initialOwner) {}

    /*//////////////////////////////////////////////////////////////
                         PERMISSIONED ACTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Change the trusted caller by calling this from the contract's owner.
     *
     * @param accounts Accounts to update trusted caller status
     * @param statuses Boolean values to update accounts with
     */
    function setTrustedCallers(address[] memory accounts, bool[] memory statuses) public onlyOwner {
        _setTrustedCallers(accounts, statuses);
    }

    /**
     * @notice Disable trustedOnly mode. Must be called by the contract's owner.
     */
    function disableTrustedOnly() external onlyOwner {
        delete trustedOnly;
        emit DisableTrustedOnly();
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Internal helper to set trusted caller. Can be used internally
     *      to set the trusted caller at construction time.
     */
    function _setTrustedCallers(address[] memory _accounts, bool[] memory _statuses) internal {
        address sender = msg.sender;
        if (_accounts.length != _statuses.length) revert Input_Length_Mismatch();
        for (uint256 i = 0; i < _accounts.length; ++i) {
            if (_accounts[i] == address(0)) revert Invalid_Address();
            isTrustedCaller[_accounts[i]] = _statuses[i];
            emit SetTrustedCaller(_accounts[i], _statuses[i], sender);
        }
    }
}