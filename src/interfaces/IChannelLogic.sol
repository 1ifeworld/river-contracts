// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ILogic} from "./ILogic.sol";

/**
 * @title IChannelLogic
 * @author Lifeworld
 */
interface IChannelLogic is ILogic {    
    function canUpdate(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool);
    function canAdd(uint256 userId, bytes32 channelUid, bytes memory data) external view returns (bool);
    function canRemove(uint256 userId, bytes32 channelUid, bytes memory data) external view returns (bool);    
}