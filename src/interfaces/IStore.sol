// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title IStore
 * @author Lifeworld
 */
interface IStore {

    //////////////////////////////////////////////////
    // WRITES
    //////////////////////////////////////////////////

    function initializeWithData(uint256 userId, bytes32 uid, bytes calldata data) external;
    function message(uint256 userId, bytes32 uid, bytes calldata data) external;

    //////////////////////////////////////////////////
    // READS
    //////////////////////////////////////////////////

    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool);
    function getUpdateAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool);
    function uri(bytes32 uid) external view returns (string memory);
}