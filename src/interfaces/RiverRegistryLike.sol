// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/**
 * @dev Minimal interface for RiverRegistry, used by the SignedKeyRequestValidator
 */
interface RiverRegistryLike {
    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Maps each address to an rid, or zero if it does not own an rid.
     */
    function idOf(address ridOwner) external view returns (uint256);

    /*//////////////////////////////////////////////////////////////
                                 VIEWS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify that a signature was produced by the custody address that owns an rid.
     *
     * @param custodyAddress   The address to check the signature of.
     * @param rid              The rid to check the signature of.
     * @param digest           The digest that was signed.
     * @param sig              The signature to check.
     *
     * @return isValid Whether provided signature is valid.
     */
    function verifyRidSignature(
        address custodyAddress,
        uint256 rid,
        bytes32 digest,
        bytes calldata sig
    ) external view returns (bool isValid);
}