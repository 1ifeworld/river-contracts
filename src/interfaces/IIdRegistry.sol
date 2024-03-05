// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title IIdRegistry
 * @author Lifeworld
 */
interface IIdRegistry {

    //////////////////////////////////////////////////
    // ERRORS
    //////////////////////////////////////////////////

    /// @dev Revert when the caller does not have the authority to perform the action.
    error Unauthorized();

    /// @dev Revert when the destination must be empty but has an rid.
    error Has_Id();

    /// @dev Revert when the caller must have an rid but does not have one.
    error Has_No_Id();

    /// @dev Revert when target rid has previously been claimed.
    error Previously_Claimed();

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    /**
     * @dev Emit an event when a new River ID is registered.
     *
     * @param to       The custody address that owns the rid.
     * @param id       The rid that was registered.
     * @param recovery The address that can initiate a recovery request for the rid.
     */
    event Register(address indexed to, uint256 id, address recovery);

    /**
     * @dev Emit an event when an rid is reserved by a host address
     *
     * @param to       The host address that reserves the rid.
     * @param id       The rid that was reserved.
     */
    event Reserve(address indexed to, uint256 id);

    /**
     * @dev Emit an event when an rid is transferred to a new custody address.
     *
     * @param from The custody address that previously owned the rid.
     * @param to   The custody address that now owns the rid.
     * @param id   The rid that was transferred.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    /**
     * @dev Emit an event when an rid is recovered.
     *
     * @param from The custody address that previously owned the rid.
     * @param to   The custody address that now owns the rid.
     * @param id   The rid that was recovered.
     */
    event Recover(address indexed from, address indexed to, uint256 indexed id);

    /**
     * @dev Emit an event when a River ID's recovery address changes. It is possible for this
     *      event to emit multiple times in a row with the same recovery address.
     *
     * @param id       The rid whose recovery address was changed.
     * @param recovery The new recovery address.
     */
    event ChangeRecoveryAddress(uint256 indexed id, address indexed recovery);
}
