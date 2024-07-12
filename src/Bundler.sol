// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {IdRegistry} from "./IdRegistry.sol";
import {KeyRegistry} from "./KeyRegistry.sol";
import {IBundler} from "./interfaces/IBundler.sol";
import {Trust} from "./abstract/Trust.sol";

/**
 * @title River Bundler
 * @dev Forked from Farcaster Bundler.sol
 */
contract Bundler is IBundler, Trust {

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @dev Revert if the caller does not have the authority to perform the action.
    error Unauthorized();

    /// @dev Revert if the caller attempts to rent zero storage units.
    error InvalidAmount();

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Contract version specified using River protocol version scheme.
     */
    string public constant VERSION = "2024.07.11";

    /*//////////////////////////////////////////////////////////////
                                IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Address of the IdRegistry contract
     */
    IdRegistry public immutable idRegistry;

    /**
     * @dev Address of the KeyRegistry contract
     */
    KeyRegistry public immutable keyRegistry;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Configure the addresses of the Registry contracts
     *
     * @param _idRegistry      Address of the IdRegistry contract
     * @param _keyRegistry     Address of the KeyRegistry contract
     * @param _initialOwner     Address of the KeyRegistry contract
     */
    constructor(
        address _idRegistry,
        address _keyRegistry,
        address _initialOwner
    ) Trust(_initialOwner) {
        idRegistry = IdRegistry(_idRegistry);
        keyRegistry = KeyRegistry(_keyRegistry);
        // address[] memory trustedAccounts = new address[](1);
        // bool[] memory statuses = new bool[](1);
        // trustedAccounts[0] = _initialOwner;
        // statuses[0] = true;
        // // setTrustedCallers(trustedAccounts, statuses);
    }

    /**
     * @notice Register an rid and multiple signers in a single transaction.
     *
     * @param registration Struct containing registration parameters: to, recovery, deadline, and signature.
     * @param signers      Array of structs containing signer parameters: keyType, key, metadataType,
     *                        metadata, deadline, and signature.
     *
     */
    function trustedRegister(
        RegistrationParams calldata registration,
        SignerParams[] calldata signers
    ) external payable onlyTrustedCaller {
        uint256 rid =
            idRegistry.trustedRegisterFor(registration.to, registration.recovery);

        uint256 signersLen = signers.length;
        for (uint256 i; i < signersLen;) {
            SignerParams calldata signer = signers[i];
            keyRegistry.trustedAddFor(
                registration.to,
                signer.keyType,
                signer.key,
                signer.metadataType,
                signer.metadata,
                signer.deadline,
                signer.sig
            );

            // We know this will not overflow because it's less than the length of the array, which is a `uint256`.
            unchecked {
                ++i;
            }
        }
    }
}