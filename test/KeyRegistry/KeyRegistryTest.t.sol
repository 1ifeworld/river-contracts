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

import "../SignedKeyRequestValidator/SignedKeyRequestValidator.t.sol";

contract KeyRegistryTest is Test, SignedKeyRequestValidatorTest {       

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////   

    KeyRegistry public keyRegistry;

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////   

    // Set-up called before each test
    function setUp() public virtual override {   
        super.setUp();
        vm.startPrank(trusted.addr);
        keyRegistry = new KeyRegistry(address(idRegistry), trusted.addr, 500);        
        keyRegistry.setTrustedCallers(trustedCallers, statuses);
        keyRegistry.setValidator(1, 1, IMetadataValidator(validator));
        vm.stopPrank();    
    }    

    //////////////////////////////////////////////////
    // SETUP TESTS
    //////////////////////////////////////////////////        

    function testInitialIdRegistry() public {
        assertEq(address(keyRegistry.idRegistry()), address(idRegistry));
    }    

    //////////////////////////////////////////////////
    // SIGNATURE BASED WRITES
    //////////////////////////////////////////////////   

    function test_eoaCustodyAddress_addFor() public {
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
        // generate addFor signature
        bytes memory addForSig = _signAdd(
            user.key,
            user.addr,
            1,
            EDDSA_PUB_KEY,
            1,
            signedKeyRequestBytes,
            deadline
        );
        // register key
        keyRegistry.addFor(user.addr, 1, EDDSA_PUB_KEY, 1, signedKeyRequestBytes, deadline, addForSig);
        // look up key data of registeedd key
        IKeyRegistry.KeyData memory keyData = keyRegistry.keyDataOf(rid, EDDSA_PUB_KEY);
        // assert key added state is correct
        assertEq(keyData.state == IKeyRegistry.KeyState.ADDED, true);
    }

    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////       

    /*
    *
    * KEY REGISTRY
    *
    */        

    /* EOA STUFF */

    function _signAdd(
        uint256 pk,
        address owner,
        uint32 keyType,
        bytes memory key,
        uint8 metadataType,
        bytes memory metadata,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        return _signAdd(pk, owner, keyType, key, metadataType, metadata, keyRegistry.nonces(owner), deadline);
    }

    function _signAdd(
        uint256 pk,
        address owner,
        uint32 keyType,
        bytes memory key,
        uint8 metadataType,
        bytes memory metadata,
        uint256 nonce,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        bytes32 digest = keyRegistry.hashTypedDataV4(
            keccak256(
                abi.encode(
                    keyRegistry.ADD_TYPEHASH(),
                    owner,
                    keyType,
                    keccak256(key),
                    metadataType,
                    keccak256(metadata),
                    nonce,
                    deadline
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        signature = abi.encodePacked(r, s, v);
        assertEq(signature.length, 65);
    }    

    // function _prepareEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     );        
    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    //     bytes memory encodedWrapper = abi.encode(wrapper);
    //     return encodedWrapper;                
    // }        


    // function _prepareEoa6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
    //     public
    //     returns (address, bytes memory)
    // {
    //     // this gets deterministic smart account address from factory
    //     CoinbaseSmartWallet undeployedLocalAcct =
    //         CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

    //     // this creates the hash that will be generated inside of id registry run time
    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
    //     );               
    //     // this creates the hash that will be generated inside of smart account run time
    //     ERC1271InputGenerator generator = new ERC1271InputGenerator(
    //         undeployedLocalAcct,
    //         idRegistryRegisterForHash,
    //         address(smartWalletFactory),
    //         abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
    //     );
    //     bytes32 smartWalletSafeHash = bytes32(address(generator).code);
    //     // this creates the signature of the owner of the smart wallet
    //     bytes memory eoaSigForOwner = _sign(_initialSigner.key, smartWalletSafeHash);
    //     // this creates the signature wrapper that is used to pass signatures inside of smart wallet runtime
    //     bytes memory encodedSignatureWrapper =
    //         abi.encode(SignatureWrapper({ownerIndex: 0, signatureData: eoaSigForOwner}));
    //     // this creates the account init data that will be used to simulate deploy of smart account
    //     bytes memory accountInitCalldata = abi.encodeCall(
    //         CoinbaseSmartWalletFactory.createAccount,
    //         (_initialOwners, 0) // owners, nonce
    //     );        
    //     // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
    //     bytes memory sigFor6492 = bytes.concat(
    //         abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
    //         ERC6492_DETECTION_SUFFIX
    //     );
    //     return (address(undeployedLocalAcct), sigFor6492);
    // }

    // /* PASSKEY STUFF */

    // function _preparePasskeySigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     );        
    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
    //     (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
    //     s = bytes32(Utils.normalizeS(uint256(s)));
    //     bytes memory sig = abi.encode(
    //         CoinbaseSmartWallet.SignatureWrapper({
    //             ownerIndex: 2,
    //             signatureData: abi.encode(
    //                 WebAuthn.WebAuthnAuth({
    //                     authenticatorData: webAuthn.authenticatorData,
    //                     clientDataJSON: webAuthn.clientDataJSON,
    //                     typeIndex: 1,
    //                     challengeIndex: 23,
    //                     r: uint256(r),
    //                     s: uint256(s)
    //                 })
    //             )
    //         })
    //     );
    //     return sig;                
    // }        


    // function _preparePasskey6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
    //     public
    //     returns (address, bytes memory)
    // {
    //     // this gets deterministic smart account address from factory
    //     CoinbaseSmartWallet undeployedLocalAcct =
    //         CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

    //     // this creates the hash that will be generated inside of id registry run time
    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
    //     );               
    //     // this creates the hash that will be generated inside of smart account run time
    //     ERC1271InputGenerator generator = new ERC1271InputGenerator(
    //         undeployedLocalAcct,
    //         idRegistryRegisterForHash,
    //         address(smartWalletFactory),
    //         abi.encodeWithSignature("createAccount(bytes[],uint256)", _initialOwners, 0)
    //     );
    //     bytes32 smartWalletSafeHash = bytes32(address(generator).code);
    //     // formats webauthn
    //     WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(smartWalletSafeHash);
    //     // creates + cleans p256 sig
    //     (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash);
    //     s = bytes32(Utils.normalizeS(uint256(s)));        
    //     // creates encoded signature wrapper
    //     bytes memory encodedSignatureWrapper = abi.encode(
    //         CoinbaseSmartWallet.SignatureWrapper({
    //             ownerIndex: 2,
    //             signatureData: abi.encode(
    //                 WebAuthn.WebAuthnAuth({
    //                     authenticatorData: webAuthn.authenticatorData,
    //                     clientDataJSON: webAuthn.clientDataJSON,
    //                     typeIndex: 1,
    //                     challengeIndex: 23,
    //                     r: uint256(r),
    //                     s: uint256(s)
    //                 })
    //             )
    //         })
    //     );        
    //     // this creates the account init data that will be used to simulate deploy of smart account
    //     bytes memory accountInitCalldata = abi.encodeCall(
    //         CoinbaseSmartWalletFactory.createAccount,
    //         (_initialOwners, 0) // owners, nonce
    //     );        
    //     // this creates the 6492 sig format that can be detected by verifiers suppriting 6492 verification
    //     bytes memory sigFor6492 = bytes.concat(
    //         abi.encode(address(smartWalletFactory), accountInitCalldata, encodedSignatureWrapper),
    //         ERC6492_DETECTION_SUFFIX
    //     );
    //     return (address(undeployedLocalAcct), sigFor6492);
    // }

    // /*
    // *
    // * KEY REGISTRY
    // *
    // */            

    // // function _prepareAddKeyEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, uint256 deadline) public view returns (bytes memory) {
    // //     // bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    // //     //     keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    // //     // );        

    // //     // set up signed key request validator metadata signature


    // //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    // //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    // //     );        
    // //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    // //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    // //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    // //     bytes memory encodedWrapper = abi.encode(wrapper);



    // //     SignedKeyRequestValidator.SignedKeyRequestMetadata memory metadata = SignedKeyRequestValidator({
    // //         requestRid: 1,
    // //         requestSigner: address(_smartWallet),
    // //         signature: ,
    // //         deadline: deadline
    // //     })

    // //     // set up key registry signature


    // //     bytes32 keyRegistryAddForHash = keyRegistry.hashTypedDataV4(
    // //         keccak256(abi.encode(
    // //             keyRegistry.ADD_TYPEHASH(), // typehash
    // //             address(_smartWallet),      // rid woner
    // //             1,                          // key type
    // //             keccak256(EDDSA_PUB_KEY),   // key hash
    // //             1,                          // key metadata type
    // //             idRegistry.nonces(address(_smartWallet)), 
    // //             deadline
    // //         )
    // //     )
    // //     );                


    // //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    // //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    // //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    // //     bytes memory encodedWrapper = abi.encode(wrapper);
    // //     return encodedWrapper;                
    // // }     


}
