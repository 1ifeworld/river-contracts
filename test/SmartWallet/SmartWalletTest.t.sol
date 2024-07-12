// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";
import {ECDSA} from "@openzeppelin/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "@openzeppelin/utils/cryptography/SignatureChecker.sol";
import "../TestSuiteSetup.sol";
import {Mock6492Verifier} from "../Mocks/Mock6492Verifier.sol";

contract SmartWalletTest is TestSuiteSetup {

    // VARIABLES
    
    Mock6492Verifier verifier;

    // SETUP

    function setUp() public virtual override {
        super.setUp();
        verifier = new Mock6492Verifier();
    }

    function test_deployFromFactoryEoaOwner() public view {
        assertEq(address(smartWallet), smartWalletFactory.getAddress(owners, nonce));
        bytes memory owner = smartWallet.ownerAtIndex(0);
        assertEq(user.addr, abi.decode(owner, (address)));
    }

    function test_verifySmartAccountEoa712Sig() public view {
        (bytes32 hash, bytes memory encodedWrapper) = _prepareEoa712Sig(user);
        bytes4 returnBytes = smartWallet.isValidSignature(hash, encodedWrapper);
        assertEq(returnBytes, ERC1271_SUCCESS);
    }

    function test_verify6492EoaSig() public {
        Account memory initialSigner = makeAccount("initialSigner");
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(initialSigner.addr);
        (address signer, bytes32 digest, bytes memory sigFor6492) = _prepareEoa6492Sig(initialSigner, initialOwners);
        bool result = verifier.isValidSig(signer, digest, sigFor6492);
        assertEq(true, result);
    }

    function test_deployFromFactoryPasskeyOwner() public view {
        assertEq(address(smartWallet), smartWalletFactory.getAddress(owners, nonce));
        bytes memory owner = smartWallet.ownerAtIndex(2);
        assertEq(passkeyOwner, owner);
    }

    function test_verifySmartAccountP256Sig() public view {
        (bytes32 digest, bytes memory sig) = _prepareP256Sig();
        bytes4 ret = smartWallet.isValidSignature(digest, sig);
        assertEq(ret, bytes4(0x1626ba7e));
    }

    function test_verifySmartAccount6492P256Sig() public {
        (address signer, bytes32 digest, bytes memory sigFor6492) = _prepare6492P256Sig();
        bool result = verifier.isValidSig(signer, digest, sigFor6492);
        assertEq(true, result);
    }

    // HELPERS
    function _prepareEoa6492Sig(Account memory _initialSigner, bytes[] memory _initialOwners)
        public
        returns (address, bytes32, bytes memory)
    {
        bytes32 digest = keccak256("mockHash");
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));
        // this sets the contract code of generator = to the replaySafeHash of the undeployedLocalAcct
        //      if it was deployed. convert to bytes32 by doing bytes32(address(generator).code))
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            digest,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        // this signs the safeReplayHash generated for the undeployed smart account by the
        //      generator helper, for the initialSigner getting set for smart account
        bytes memory eoaSigForOwner = _sign(_initialSigner.key, bytes32(address(generator).code));
        bytes memory encodedSignatureWrapper =
            abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner}));
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), digest, sigFor6492);
    }

    // TODO: this function will only work with the global account variable
    //      trying to use this to prepare sigs to be verified by other acccounts will not work
    //      due to how replaySafeHash works
    function _prepareEoa712Sig(Account memory eoaOwner) public view returns (bytes32, bytes memory) {
        bytes32 digest = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eea4;
        // NOTE: we aren't actually using the account contract here
        //       we are just accessing replaySafeHash from it
        // TODO: cleaner version of test would let us access replaySafeHash from a library or
        //       separately set function
        bytes32 toSign = smartWallet.replaySafeHash(digest);
        bytes memory eoaSigForOwner = _sign(eoaOwner.key, toSign);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner});
        bytes memory encodedWrapper = abi.encode(wrapper);
        return (digest, encodedWrapper);
    }

    function _prepareP256Sig() public view returns (bytes32, bytes memory) {
        bytes32 digest = keccak256("mock p256 hash");
        bytes32 toSign = smartWallet.replaySafeHash(digest);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(toSign);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: passkeyOwnerIndex,
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
        return (digest, sig);
    }

    function _prepare6492P256Sig() public returns (address, bytes32, bytes memory) {
        bytes32 digest = keccak256("mock p256 hash");
        bytes[] memory _intialOwners = new bytes[](1);
        _intialOwners[0] = passkeyOwner;
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_intialOwners, 0) // owners, nonce
        );
        CoinbaseSmartWallet undeployedLocalAcct = CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(owners, 0)));
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            digest,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", owners, 0)
        );
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(bytes32(address(generator).code));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        bytes memory encodedSignatureWrapper = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: passkeyOwnerIndex,
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

        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), digest, sigFor6492);
    }
}