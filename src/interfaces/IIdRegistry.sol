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

    //////////////////////////////////////////////////
    // EVENTS
    //////////////////////////////////////////////////

    /**
     * @dev Emit an event when a new River ID is registered.
     *
     *      Hubs listen for this and update their address-to-rid mapping by adding `to` as the
     *      current owner of `id`. Hubs assume the invariants:
     *
     *      1. Two Register events can never emit with the same `id`
     *
     *      2. Two Register(alice, ..., ...) cannot emit unless a Transfer(alice, bob, ...) emits
     *          in between, where bob != alice.
     *
     * @param to       The custody address that owns the rid
     * @param id       The rid that was registered.
     * @param recovery The address that can initiate a recovery request for the rid.
     */
    event Register(address indexed to, uint256 id, address recovery);

    /**
     * @dev Emit an event when an rid is transferred to a new custody address.
     *
     *      Hubs listen to this event and atomically change the current owner of `id`
     *      from `from` to `to` in their address-to-rid mapping. Hubs assume the invariants:
     *
     *      1. A Transfer(..., alice, ...) cannot emit if the most recent event for alice is
     *         Register (alice, ..., ...)
     *
     *      2. A Transfer(alice, ..., id) cannot emit unless the most recent event with that id is
     *         Transfer(..., alice, id) or Register(alice, id, ...)
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
