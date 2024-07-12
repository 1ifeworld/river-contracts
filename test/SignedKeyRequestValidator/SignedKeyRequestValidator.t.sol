// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import "../TestSuiteSetup.sol";

import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {IdRegistry} from "../../src/IdRegistry.sol";
import {IIdRegistry} from "../../src/interfaces/IIdRegistry.sol";
import {KeyRegistry} from "../../src/KeyRegistry.sol";
import {IKeyRegistry} from "../../src/interfaces/IKeyRegistry.sol";
import {SignedKeyRequestValidator} from "../../src/validators/SignedKeyRequestValidator.sol";
import {IMetadataValidator} from "../../src/interfaces/IMetadataValidator.sol";
import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";
import "../IdRegistry/IdRegistryTestSuite.sol";

contract SignedKeyRequestValidatorTest is IdRegistryTestSuite {

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////

    bytes EDDSA_PUB_KEY = hex"b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f25e5f92444cde";
    SignedKeyRequestValidator public validator;

    //////////////////////////////////////////////////
    // INIT TESTS
    //////////////////////////////////////////////////

    function test_initialIdRegistry() public view {
        assertEq(address(validator.idRegistry()), address(idRegistry));
    }

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////

    function test_eoaCustodyAddress_validate() public {
        uint256 deadline = _deadline();
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // generate registerfor signature
        bytes memory sig = _signRegister(user.key, user.addr, trusted.addr, deadline);
        // register id
        uint256 rid = idRegistry.registerFor(user.addr, trusted.addr, _deadline(), sig);
        // get signature for signedKeyRequestBytes
        bytes memory signedMetadata = _signMetadata(user.key, rid, EDDSA_PUB_KEY, deadline);
        // format signedKeyRequestBytes
        bytes memory signedKeyRequestBytes = _formatSignedKeyRequestBytes(rid, user.addr, signedMetadata, deadline);
        // call validator
        bool response = validator.validate(0, EDDSA_PUB_KEY, signedKeyRequestBytes);
        assertEq(response, true);
    }

    function test_smartWalletCustodyWithEoaSigner_validate() public {
        uint256 deadline = _deadline();
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // generate registerfor signature
        bytes memory sig = _signRegister(user.key, user.addr, trusted.addr, deadline);
        // register id
        uint256 rid = idRegistry.registerFor(user.addr, trusted.addr, _deadline(), sig);
        // get signature for signedKeyRequestBytes
        bytes memory signedMetadata = _signMetadata(user.key, rid, EDDSA_PUB_KEY, deadline);
        // format signedKeyRequestBytes
        bytes memory signedKeyRequestBytes = _formatSignedKeyRequestBytes(rid, user.addr, signedMetadata, deadline);
        // call validator
        bool response = validator.validate(0, EDDSA_PUB_KEY, signedKeyRequestBytes);
        assertEq(response, true);
    }    

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////

    function _signMetadata(uint256 pk, uint256 requestingFid, bytes memory signerPubKey, uint256 deadline)
        internal
        view
        returns (bytes memory signature)
    {
        bytes32 digest = validator.hashTypedDataV4(
            keccak256(abi.encode(validator.METADATA_TYPEHASH(), requestingFid, keccak256(signerPubKey), deadline))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);
    }

    function _formatSignedKeyRequestBytes(
        uint256 requestRid,
        address requestSigner,
        bytes memory signature,
        uint256 deadline
    ) internal pure returns (bytes memory) {
        SignedKeyRequestValidator.SignedKeyRequestMetadata memory metadata = SignedKeyRequestValidator
            .SignedKeyRequestMetadata({
            requestRid: requestRid,
            requestSigner: requestSigner,
            signature: signature,
            deadline: deadline
        });
        return abi.encode(metadata);
    }
}