// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title Salt
 * @author Lifeworld 
 */
abstract contract Salt {
    bytes32 constant public CHANNEL_SALT = keccak256("CHANNEL_SALT");
    bytes32 constant public ITEM_SALT = keccak256("ITEM_SALT");
}