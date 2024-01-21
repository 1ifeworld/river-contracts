// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IStore} from "./IStore.sol";

/**
 * @title IChannelStore
 * @author Lifeworld
 */
interface IChannelStore is IStore {    
    function getAddAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool);
    function getRemoveAccess(uint256 userId, address origin, bytes32 uid, bytes memory data) external view returns (bool);
}