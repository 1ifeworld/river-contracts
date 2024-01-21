// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {ILogic} from "./ILogic.sol";

/**
 * @title IChannelLogic
 * @author Lifeworld
 */
interface IChannelLogic is ILogic {    
    function settingsAccess(uint256 userId, bytes32 uid) external view returns (bool);
    function addAccess(uint256 userId, bytes32 channelUid, bytes memory data) external view returns (bool);
    function removeAccess(uint256 userId, bytes32 channelUid, bytes memory data) external view returns (bool);    
}