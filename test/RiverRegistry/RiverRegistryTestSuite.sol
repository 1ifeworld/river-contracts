// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.23;

import {ERC1271InputGenerator} from "@smart-wallet/utils/ERC1271InputGenerator.sol";
import {CoinbaseSmartWallet} from "@smart-wallet/CoinbaseSmartWallet.sol";
import {CoinbaseSmartWalletFactory} from "@smart-wallet/CoinbaseSmartWalletFactory.sol";
import {WebAuthn} from "@webauthn-sol/src/WebAuthn.sol";
import "@webauthn-sol/test/Utils.sol";
import {RiverRegistry} from "../../src/RiverRegistry.sol";
import {IRiverRegistry} from "../../src/interfaces/IRiverRegistry.sol";
import {TestSuiteSetup} from "../TestSuiteSetup.sol";

abstract contract RiverRegistryTestSuite is TestSuiteSetup {
    RiverRegistry riverRegistry;
    address[] trustedCallers;

    function setUp() public virtual override {
        super.setUp();
        trustedCallers = new address[](1);
        trustedCallers[0] = relayer.addr;
        riverRegistry = new RiverRegistry(trusted.addr, trustedCallers, payout.addr, 0);
    }

    //////////////////////////////////////////////////
    // TEST HELPERS
    //////////////////////////////////////////////////             

    function randomishAccount(uint256 entropy) public pure returns (address) {
        bytes32 hash = keccak256(abi.encode(entropy));
        return address(uint160(uint256(hash)));
    }  

    function generateKeyInits(uint256 numKeys) public pure returns (IRiverRegistry.KeyInit[][] memory) {
        IRiverRegistry.KeyInit[][] memory keys = new IRiverRegistry.KeyInit[][](numKeys);
        for (uint256 i; i < numKeys; ++i) {
            IRiverRegistry.KeyInit[] memory init = new IRiverRegistry.KeyInit[](1);
            init[0] = IRiverRegistry.KeyInit({
                keyType: 1,
                key: abi.encode(i + 1)
            });
            keys[i] = init;
        }
        return keys;
    }

    function _prepMigrateForAccounts(uint256 numAccounts) internal {
        for (uint256 i; i < numAccounts; ++i) {
            address randomAccount = randomishAccount(i);
            riverRegistry.trustedPrepMigration(randomAccount, recovery.addr);
        }        
    }    

    /* EOA STUFF */

    function _signRegister(
        uint256 pk,
        address to,
        address recovery,
        IRiverRegistry.KeyInit[] memory keyInits,
        uint256 deadline
    ) internal view returns (bytes memory signature) {
        address signer = vm.addr(pk);
        bytes32 digest = riverRegistry.hashTypedDataV4(
            keccak256(abi.encode(riverRegistry.REGISTER_TYPEHASH(), to, recovery, keyInits, riverRegistry.nonces(signer), deadline))
        );
        signature = _sign(pk, digest);
    }         

    function _prepareEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, IRiverRegistry.KeyInit[] memory keyInits, uint256 deadline) public view returns (bytes memory) {

        bytes32 riverRegistryRegisterForHash = riverRegistry.hashTypedDataV4(
            keccak256(abi.encode(riverRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, keyInits, riverRegistry.nonces(address(_smartWallet)), deadline))
        );                
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(riverRegistryRegisterForHash);
        bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
        bytes memory encodedWrapper = abi.encode(wrapper);
        return encodedWrapper;                
    }        

    function _prepareEoa6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, IRiverRegistry.KeyInit[] memory keyInits, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 riverRegistryRegisterForHash = riverRegistry.hashTypedDataV4(
            keccak256(abi.encode(riverRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, keyInits, riverRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            riverRegistryRegisterForHash,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        bytes32 smartWalletSafeHash = bytes32(address(generator).code);
        // this creates the signature of the owner of the smart wallet
        bytes memory eoaSigForOwner = _sign(_initialSigner.key, smartWalletSafeHash);
        // this creates the signature wrapper that is used to pass signatures inside of smart wallet runtime
        bytes memory encodedSignatureWrapper =
            abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner}));
        // this creates the account init data that will be used to simulate deploy of smart account
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );        
        // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), sigFor6492);
    }

    // /* PASSKEY STUFF */

    function _preparePasskeySigForSmartWallet(CoinbaseSmartWallet _smartWallet, address recovery, IRiverRegistry.KeyInit[] memory keyInits, uint256 deadline) public view returns (bytes memory) {
        bytes32 riverRegistryRegisterForHash = riverRegistry.hashTypedDataV4(
            keccak256(abi.encode(riverRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, keyInits, riverRegistry.nonces(address(_smartWallet)), deadline))
        );        
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(riverRegistryRegisterForHash);
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));
        bytes memory sig = abi.encode(
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
        return sig;                
    }        

    function _preparePasskey6492SigForSmartWallet(bytes[] memory _initialOwners, address recovery, IRiverRegistry.KeyInit[] memory keyInits, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 riverRegistryRegisterForHash = riverRegistry.hashTypedDataV4(
            keccak256(abi.encode(riverRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, keyInits, riverRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            riverRegistryRegisterForHash,
            address(smartWalletFactory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
        );
        bytes32 smartWalletSafeHash = bytes32(address(generator).code);
        // formats webauthn
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
        // creates + cleans p256 sig
        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
        s = bytes32(Utils.normalizeS(uint256(s)));        
        // creates encoded signature wrapper
        bytes memory encodedSignatureWrapper = abi.encode(
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
        // this creates the account init data that will be used to simulate deploy of smart account
        bytes memory accountInitCalldata = abi.encodeCall(
            CoinbaseSmartWalletFactory.createAccount,
            (_initialOwners, 0) // owners, nonce
        );        
        // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
        bytes memory sigFor6492 = bytes.concat(
            abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
            ERC6492_DETECTION_SUFFIX
        );
        return (address(undeployedLocalAcct), sigFor6492);
    }
}