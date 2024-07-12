// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

interface IBundler {
    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Data needed to trusted register a signer with the key registry
    struct SignerData {
        uint32 keyType;
        bytes key;
        uint8 metadataType;
        bytes metadata;
    }

    /// @notice Data needed to register an rid with signature.
    struct RegistrationParams {
        address to;
        address recovery;
        uint256 deadline;
        bytes sig;
    }

    /// @notice Data needed to add a signer with signature.
    struct SignerParams {
        uint32 keyType;
        bytes key;
        uint8 metadataType;
        bytes metadata;
        uint256 deadline;
        bytes sig;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Contract version specified in the River protocol version scheme.
     */
    function VERSION() external view returns (string memory);

    /*//////////////////////////////////////////////////////////////
                                 REGISTRATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Register an rid and multiple signers to an address in a single transaction.
     *
     * @param registration Struct containing registration parameters: to, recovery, deadline, and signature.
     * @param signers      Array of structs containing signer parameters: keyType, key, metadataType, metadata, deadline, and signature.
     *
     */
    function register(
        RegistrationParams calldata registration,
        SignerParams[] calldata signers
    ) external payable;
}