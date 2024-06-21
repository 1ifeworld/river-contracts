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
import {WebAuthn} from "webauthn-sol/WebAuthn.sol";

contract SmartWalletSignatureValidation is TestSuiteSetup {
    CoinbaseSmartWalletFactory smartWalletfactory = new CoinbaseSmartWalletFactory(address(new CoinbaseSmartWallet()));
    bytes[] owners;
    Mock6492Verifier verifier;
    CoinbaseSmartWallet account;
    uint256 nonce;
    uint256 passkeyOwnerIndex;

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
        passkeyOwnerIndex = 2;
        verifier = new Mock6492Verifier();
        account = smartWalletfactory.createAccount(owners, nonce);
    }

    function test_deployFromFactoryEoaOwner() public view {
        assertEq(address(account), smartWalletfactory.getAddress(owners, nonce));
        bytes memory owner = account.ownerAtIndex(0);
        assertEq(user.addr, abi.decode(owner, (address)));
    }

    function test_verifySmartAccountEoa712Sig() public view {
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

    function test_deployFromFactoryPasskeyOwner() public view {
        assertEq(address(account), smartWalletfactory.getAddress(owners, nonce));
        bytes memory owner = account.ownerAtIndex(2);
        assertEq(passkeyOwner, owner);
    }

    function test_verifySmartAccountP256Sig() public view {
        (bytes32 digest, bytes memory sig) = _prepareP256Sig();
        bytes4 ret = account.isValidSignature(digest, sig);
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
    function _prepareEoa712Sig(Account memory eoaOwner) public view returns (bytes32, bytes memory) {
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

    function _prepareP256Sig() public view returns (bytes32, bytes memory) {
        bytes32 digest = keccak256("mock p256 hash");
        bytes32 toSign = account.replaySafeHash(digest);
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
        CoinbaseSmartWallet undeployedLocalAcct = CoinbaseSmartWallet(payable(smartWalletfactory.getAddress(owners, 0)));
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            digest,
            address(smartWalletfactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", owners, 0)
        );
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(bytes32(address(generator).code));
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));

        bytes memory sigFor6492 = abi.encode(
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

        return (address(undeployedLocalAcct), digest, sigFor6492);
    }







    // bytes challenge = abi.encode(0x6454ad9229833dd1eadcd33dd782a4ca476caae9f535c7a57e13c4131a6a1850);
    // bytes challenge = abi.encode(0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf);

    function test_safari() public {
        uint256 x = 30244708688309919677569886957912731198129078400964522906942980088228172369352;
        uint256 y = 85115680486173964600348175480743578652400648939086283276039309814227777412949;
        // uint256 x = 28573233055232466711029625910063034642429572463461595413086259353299906450061;        
        // uint256 y = 39367742072897599771788408398752356480431855827262528811857788332151452825281;
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            // authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000101",
            authenticatorData: hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631900000000",
            // clientDataJSON: string.concat(
            //     '{"type":"webauthn.get","challenge":"', Base64Url.encode(challenge), '","origin":"http://localhost:3005"}'
            // ),
            // clientDataJSON: "{type:webauthn.get,challenge:ZFStkimDPdHq3NM914Kkykdsqun1NcelfhPEExpqGFA,origin:http://localhost:8081}",
            clientDataJSON: "{type:webauthn.get,challenge:Eg,origin:http://localhost:8081}",
            challengeIndex: 23,
            typeIndex: 1,
            // r: 43684192885701841787131392247364253107519555363555461570655060745499568693242,
            r: 73396795033680543686572560637862858395050875993898693824787047558107084248906,
            // s: 22655632649588629308599201066602670461698485748654492451178007896016452673579
            s: 102800634548387712854952698226392037958674589942381642018119459263400000737063
        });
        assertTrue(auth.typeIndex == 1);
        // assertTrue(WebAuthn.verify("Eg", false, auth, x, y));
    }    
}
