// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title ILogic
 * @author Lifeworld
 */
interface ILogic {    
    function initializeWithData(uint256 userId, bytes32 channelHash, bytes memory data) external;
    function canAdd(uint256 userId, bytes32 channelhash) external view returns (bool);
    function canRemove(uint256 userId, bytes32 channelHash) external view returns (bool);
    function canUpdate(uint256 userId, bytes32 channelhash) external view returns (bool);
}