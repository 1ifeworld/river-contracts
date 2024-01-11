// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title DelegateRegistry
 * @author Lifeworld
 */
contract DelegateRegistry {
    // make this specific to specific func selectors and targets!!
    //      ex: can only all "newItems" or "add" on the itemRegistry
    mapping(uint256 userId => address delegate) public delegateOf;
}