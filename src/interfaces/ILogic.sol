// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title ILogic
 * @author Lifeworld
 */
interface ILogic {    
    function initializeWithData(uint256 userId, bytes32 uid, bytes memory data) external;
    function updateAccess(uint256 userId, bytes32 uid) external view returns (bool);
}