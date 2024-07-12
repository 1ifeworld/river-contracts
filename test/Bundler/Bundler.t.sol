// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {Bundler, IBundler} from "../../src/Bundler.sol";
import {IdRegistry} from "../../src/IdRegistry.sol";
import {KeyRegistry} from "../../src/KeyRegistry.sol";
import {BundlerTestSuite} from "./BundlerTestSuite.sol";

/* solhint-disable state-visibility */

contract BundlerTest is BundlerTestSuite {


    /*//////////////////////////////////////////////////////////////
                               PARAMETERS
    //////////////////////////////////////////////////////////////*/

    function testHasIDRegistry() public {
        assertEq(address(bundler.idRegistry()), address(idRegistry));
    }

    function testHasKeyRegistry() public {
        assertEq(address(bundler.keyRegistry()), address(keyRegistry));
    }

    /*//////////////////////////////////////////////////////////////
                                REGISTER
    //////////////////////////////////////////////////////////////*/


    function test_trustedRegister() public {
        bytes memory emptySig = new bytes(0);
        uint256 deadline = _deadline();

        IBundler.SignerParams[] memory signers = new IBundler.SignerParams[](1);
        signers[0] = IBundler.SignerParams({
            keyType: 1,
            key: EDDSA_PUB_KEY,
            metadataType: 1,
            metadata: bytes("supposed to be signed key request"),
            deadline: deadline,
            sig: emptySig // not getting checked in trusted pathway
        });

        vm.prank(trusted.addr);
        bundler.trustedRegister(
            IBundler.RegistrationParams({to: address(smartWallet), recovery: recovery.addr, deadline: deadline, sig: emptySig}),
            signers
        );

        _assertSuccessfulRegistration(address(smartWallet), recovery.addr);
    }
}

    // /// @notice Data needed to trusted register a signer with the key registry
    // struct SignerData {
    //     uint32 keyType;
    //     bytes key;
    //     uint8 metadataType;
    //     bytes metadata;
    // }

    // /// @notice Data needed to register an rid with signature.
    // struct RegistrationParams {
    //     address to;
    //     address recovery;
    //     uint256 deadline;
    //     bytes sig;
    // }

    // /// @notice Data needed to add a signer with signature.
    // struct SignerParams {
    //     uint32 keyType;
    //     bytes key;
    //     uint8 metadataType;
    //     bytes metadata;
    //     uint256 deadline;
    //     bytes sig;
    // }