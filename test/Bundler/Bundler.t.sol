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

    // function _generateSigners(
    //     uint256 accountPk,
    //     address account,
    //     uint256 deadline,
    //     uint256 numSigners
    // ) internal returns (IBundler.SignerParams[] memory) {
    //     IBundler.SignerParams[] memory signers = new IBundler.SignerParams[](
    //         numSigners
    //     );
    //     uint256 nonce = keyRegistry.nonces(account);

    //     // The duplication below is ugly but necessary to work around a stack too deep error.
    //     for (uint256 i = 0; i < numSigners; i++) {
    //         _registerValidator(uint32(i + 1), uint8(i + 1));
    //         signers[i] = IBundler.SignerParams({
    //             keyType: uint32(i + 1),
    //             key: abi.encodePacked("key", keccak256(abi.encode(i))),
    //             metadataType: uint8(i + 1),
    //             metadata: abi.encodePacked("metadata", keccak256(abi.encode(i))),
    //             deadline: deadline,
    //             sig: _signAdd(
    //                 accountPk,
    //                 account,
    //                 uint32(i + 1),
    //                 abi.encodePacked("key", keccak256(abi.encode(i))),
    //                 uint8(i + 1),
    //                 abi.encodePacked("metadata", keccak256(abi.encode(i))),
    //                 nonce + i,
    //                 deadline
    //                 )
    //         });
    //     }
    //     return signers;
    // }

    // function testFuzzRegister(
    //     address caller,
    //     uint256 accountPk,
    //     address recovery,
    //     uint256 storageUnits,
    //     uint8 _numSigners,
    //     uint40 _deadline
    // ) public {
    function testFuzzRegister(
        address caller,
        uint256 accountPk,
        address recovery,
        uint256 storageUnits,
        uint8 _numSigners,
        uint40 _deadline
    ) public {
        uint256 numSigners = bound(_numSigners, 0, 10);
        accountPk = _boundPk(accountPk);
        vm.assume(caller != address(bundler)); // the bundle registry cannot call itself

        // State: Trusted Registration is disabled in ID registry
        vm.prank(trusted.addr);
        idRegistry.disableTrustedOnly();

        address account = vm.addr(accountPk);
        uint256 deadline = _boundDeadline(_deadline);
        bytes memory registerSig = _signRegister(accountPk, account, recovery, deadline);

        // IBundler.SignerParams[] memory signers = _generateSigners(accountPk, account, deadline, numSigners);

        // vm.prank(caller);
        // bundler.register(
        //     IBundler.RegistrationParams({to: account, recovery: recovery, deadline: deadline, sig: registerSig}),
        //     signers
        // );

        // _assertSuccessfulRegistration(account, recovery);
    }
}