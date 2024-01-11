// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title ILogic
 * @author Lifeworld
 */
interface ILogic {
    function canAdd(uint256 channelId, uint256 userId) external view returns (bool);
    function canRemove(uint256 channelId, uint256 userId) external view returns (bool);
    function initializeWithData(uint256 userId, uint256 channelId, bytes memory data) external;
}