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
    bytes32 EDDSA_PUB_KEY_HASH = keccak256(EDDSA_PUB_KEY);
    SignedKeyRequestValidator public validator;

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////

    function setUp() public virtual override {
        super.setUp();
        validator = new SignedKeyRequestValidator(address(idRegistry), trusted.addr);
    }

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
        uint256 rid = idRegistry.registerFor(user.addr, trusted.addr, deadline, sig);
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
        // prepare reigster sig for user
        bytes memory sig = _prepareEoaSigForSmartWallet(smartWallet, user, recovery.addr, deadline);
        // register id to user
        uint256 rid = idRegistry.registerFor(address(smartWallet), recovery.addr, deadline, sig);
        // use helper to get signedjey request bytes
        bytes memory signedKeyRequestBytes = _prepValidateEoaSigForSmartWallet(user, smartWallet, rid, deadline);
        // call validator
        bool response = validator.validate(0, EDDSA_PUB_KEY, signedKeyRequestBytes);
        assertEq(response, true);
    }

    function test_smartWalletCustodyWithPasskeySigner_validate() public {
        uint256 deadline = _deadline();
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // prepare reigster sig for user
        bytes memory sig = _prepareEoaSigForSmartWallet(smartWallet, user, recovery.addr, deadline);
        // register id to user
        uint256 rid = idRegistry.registerFor(address(smartWallet), recovery.addr, deadline, sig);
        // use helper to get signedjey request bytes
        bytes memory signedKeyRequestBytes = _prepValidatePasskeySigForSmartWallet(smartWallet, rid, deadline);
        // call validator
        bool response = validator.validate(0, EDDSA_PUB_KEY, signedKeyRequestBytes);
        assertEq(response, true);
    }    

    function test_erc6492_smartWalletCustodyWithEoaSigner_validate() public {
        uint256 deadline = _deadline();
        // start prank as trusted calle
        vm.startPrank(trusted.addr);
        // prepare reigster sig for user
        (address undeployedSmartWallet, bytes memory sig) = _prepareEoa6492SigForSmartWallet(user, owners, recovery.addr, deadline);
        // register id to user
        uint256 rid = idRegistry.registerFor(address(undeployedSmartWallet), recovery.addr, deadline, sig);
        // use helper to get signedjey request bytes
        // bytes memory signedKeyRequestBytes = _prepValidateEoaSigForSmartWallet(user, undeployedSmartWallet, rid, deadline);
        (, bytes memory signedKeyRequestBytes) = _prepValidateEoa6492SigForSmartWallet(user, owners, rid, deadline);
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

    function _prepValidateEoaSigForSmartWallet(
        Account memory eoaForSmartWallet,
        CoinbaseSmartWallet wallet,
        uint256 rid,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 validatorMetadataTypeHash = validator.hashTypedDataV4(
            keccak256(abi.encode(validator.METADATA_TYPEHASH(), rid, EDDSA_PUB_KEY_HASH, deadline))
        );
        bytes32 smartWalletSafeHash = wallet.replaySafeHash(validatorMetadataTypeHash);
        bytes memory metadataEoaSig = _sign(eoaForSmartWallet.key, smartWalletSafeHash);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: metadataEoaSig});
        bytes memory encodedWrapper = abi.encode(wrapper);
        bytes memory signedKeyRequestBytes =
            _formatSignedKeyRequestBytes(rid, address(wallet), encodedWrapper, deadline);
        return signedKeyRequestBytes;
    }

    function _prepValidateEoa6492SigForSmartWallet(
        Account memory _initialSigner,        
        bytes[] memory _initialOwners,        
        uint256 rid,
        uint256 deadline
    ) internal returns (address, bytes memory) {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));
        bytes32 validatorMetadataTypeHash = validator.hashTypedDataV4(
            keccak256(abi.encode(validator.METADATA_TYPEHASH(), rid, EDDSA_PUB_KEY_HASH, deadline))
        );      

        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            validatorMetadataTypeHash,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        bytes32 smartWalletSafeHash = bytes32(address(generator).code);
        bytes memory metadataEoaSig = _sign(_initialSigner.key, smartWalletSafeHash);
        bytes memory encodedWrapper = abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: metadataEoaSig}));
        // this creates the account init data that will be used to simulate deploy of smart account
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );        
        // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        bytes memory signedKeyRequestBytes =
            _formatSignedKeyRequestBytes(rid, address(undeployedLocalAcct), sigFor6492, deadline);
        return (address(undeployedLocalAcct), signedKeyRequestBytes);        
    }    

    function _prepValidatePasskeySigForSmartWallet(
        CoinbaseSmartWallet wallet,
        uint256 rid,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 validatorMetadataTypeHash = validator.hashTypedDataV4(
            keccak256(abi.encode(validator.METADATA_TYPEHASH(), rid, EDDSA_PUB_KEY_HASH, deadline))
        );
        bytes32 smartWalletSafeHash = wallet.replaySafeHash(validatorMetadataTypeHash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory encodedWrapper = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 2,
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData,
                        clientDataJSON: webAuthn.clientDataJSON,
                        typeIndex: 1,
                        challengeIndex: 23,
                        r: uint256(r),
                        s: uint256(s)
                    })
                )
            })
        );        
        bytes memory signedKeyRequestBytes =
            _formatSignedKeyRequestBytes(rid, address(wallet), encodedWrapper, deadline);   
        return signedKeyRequestBytes;
    }    
}
