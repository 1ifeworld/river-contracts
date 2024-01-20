// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @title IStore
 * @author Lifeworld
 */
interface IStore {
    function initialize(uint256 userId, bytes32 uid, bytes calldata data) external;
    function message(uint256 userId, bytes32 uid, bytes calldata data) external;
    function getReplaceAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool);
    function getMessageAccess(uint256 userId, bytes32 uid, bytes memory data) external view returns (bool);
    function uri(bytes32 uid) external view returns (string memory);
    // function getUri(address origin, bytes32 uid) external view returns (bool);
}