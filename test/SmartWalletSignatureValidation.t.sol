// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "webauthn-sol/../test/Utils.sol";
import "./TestSuiteSetup.sol";
import {CoinbaseSmartWalletFactory} from "smart-wallet/src/CoinbaseSmartWalletFactory.sol";
import {CoinbaseSmartWallet} from "smart-wallet/src/CoinbaseSmartWallet.sol";
import {ERC1271InputGenerator} from "smart-wallet/src/utils/ERC1271InputGenerator.sol";
import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol";

import {Mock6492Verifier} from "./Mocks/Mock6492Verifier.sol";

contract SmartWalletSignatureValidation is TestSuiteSetup {
    CoinbaseSmartWalletFactory smartWalletfactory = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
    bytes[] owners;
    Mock6492Verifier verifier;
    CoinbaseSmartWallet account;
    uint256 nonce;

    struct SignatureWrapper {
        /// @dev The index of the owner that signed, see `MultiOwnable.ownerAtIndex`
        uint256 ownerIndex;
        /// @dev If `MultiOwnable.ownerAtIndex` is an Ethereum address, this should be `abi.encodePacked(r, s, v)`
        ///      If `MultiOwnable.ownerAtIndex` is a public key, this should be `abi.encode(WebAuthnAuth)`.
        bytes signatureData;
    }

    bytes32 public ERC6492_DETECTION_SUFFIX = 0x6492649264926492649264926492649264926492649264926492649264926492;
    bytes4 public ERC1271_SUCCESS = 0x1626ba7e;

    function setUp() public virtual override {
        nonce = 0;
        owners.push(abi.encode(user.addr));
        owners.push(abi.encode(trusted.addr));
        owners.push(passkeyOwner);
        verifier = new Mock6492Verifier();
        account = smartWalletfactory.createAccount(owners, nonce);
    }

    function test_deployFromFactoryEoaOwner() public {
        assertEq(address(account), smartWalletfactory.getAddress(owners, nonce));
        bytes memory owner = account.ownerAtIndex(0);
        assertEq(user.addr, abi.decode(owner, (address)));
    }

    function test_verifySmartAccountEoa712Sig() public {
        (bytes32 hash, bytes memory encodedWrapper) = _prepareEoa712Sig(user);
        bytes4 returnBytes = account.isValidSignature(hash, encodedWrapper);
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

    /*
        Next steps
        1. get the following functions to work using hardcoded values from cb test suite
            - function test_deployFromFactoryPasskeyOwner
            - function test_verifySmartAccountP256Sig
            - function test_verifySmartAccount6492P256Sig
        2. clean up test suite for readability + functionality
        3. push up to github
    */

    function test_deployFromFactoryPasskeyOwner() public {
        assertEq(address(account), smartWalletfactory.getAddress(owners, nonce));
        bytes memory owner = account.ownerAtIndex(2);
        assertEq(passkeyOwner, owner);
    }

    function test_verifySmartAccountP256Sig() public {}

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
            CoinbaseSmartWallet(payable(smartWalletfactory.getAddress(_initialOwners, 0)));
        // this sets the contract code of generator = to the replaySafeHash of the undeployedLocalAcct
        //      if it was deployed. convert to bytes32 by doing bytes32(address(generator).code))
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            digest,
            address(smartWalletfactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        // this signs the safeReplayHash generated for the undeployed smart account by the
        //      generator helper, for the initialSigner getting set for smart account
        bytes memory eoaSigForOwner = _sign(_initialSigner.key, bytes32(address(generator).code));
        bytes memory encodedSignatureWrapper =
            abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner}));
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletfactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), digest, sigFor6492);
    }

    // TODO: this function will only work with the global account variable
    //      trying to use this to prepare sigs to be verified by other acccounts will not work
    //      due to how replaySafeHash works
    function _prepareEoa712Sig(Account memory eoaOwner) public returns (bytes32, bytes memory) {
        bytes32 digest = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eea4;
        // NOTE: we aren't actually using the account contract here
        //       we are just accessing replaySafeHash from it
        // TODO: cleaner version of test would let us access replaySafeHash from a library or
        //       separately set function
        bytes32 toSign = account.replaySafeHash(digest);
        bytes memory eoaSigForOwner = _sign(eoaOwner.key, toSign);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner});
        bytes memory encodedWrapper = abi.encode(wrapper);
        return (digest, encodedWrapper);
    }
}
