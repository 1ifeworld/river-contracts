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

contract KeyRegistryTest is Test, TestSuiteSetup {       

    //////////////////////////////////////////////////
    // CONSTANTS
    //////////////////////////////////////////////////       

    bytes EDDSA_PUB_KEY = 
        hex"b7a3c12dc0c8c748ab07525b701122b88bd78f600c76342d27f25e5f92444cde";

    //////////////////////////////////////////////////
    // STORAGE
    //////////////////////////////////////////////////   

    /* contracts + accounts */
    IdRegistry public idRegistry;
    KeyRegistry public keyRegistry;
    SignedKeyRequestValidator public validator;
    CoinbaseSmartWalletFactory smartWalletFactory;
    CoinbaseSmartWallet smartWallet;
    bytes[] owners;
    uint256 nonce;

    //////////////////////////////////////////////////
    // SETUP
    //////////////////////////////////////////////////   

    // Set-up called before each test
    function setUp() public {   
        // setup fork
        uint256 baseSepoliaFork = vm.createFork('https://sepolia.base.org');
        vm.selectFork(baseSepoliaFork);
        smartWalletFactory = CoinbaseSmartWalletFactory(0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a);       
        // variavles
        nonce = 0;
        owners.push(abi.encode(user.addr));
        owners.push(abi.encode(trusted.addr));
        owners.push(passkeyOwner);
        smartWallet = smartWalletFactory.createAccount(owners, nonce);
        // trusted caller variable setup
        address[] memory trustedCallers = new address[](1);
        trustedCallers[0] = trusted.addr;
        bool[] memory statuses = new bool[](1);
        statuses[0] = true;        
        // deploy + setup id + key registry + metadata validator        
        vm.startPrank(trusted.addr);
        idRegistry = new IdRegistry(trusted.addr);  
        keyRegistry = new KeyRegistry(address(idRegistry), trusted.addr, 500);
        idRegistry.setTrustedCallers(trustedCallers, statuses);
        keyRegistry.setTrustedCallers(trustedCallers, statuses);
        validator = new SignedKeyRequestValidator(address(idRegistry), trusted.addr);
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

    // function testFuzzAdd(
    //     address to,
    //     address recovery,
    //     uint32 keyType,
    //     bytes calldata key,
    //     uint8 metadataType,
    //     bytes memory metadata
    // ) public {
    //     keyType = uint32(bound(keyType, 1, type(uint32).max));
    //     metadataType = uint8(bound(metadataType, 1, type(uint8).max));

    //     uint256 fid = _registerFid(to, recovery);
    //     _registerValidator(keyType, metadataType);

    //     vm.expectEmit();
    //     emit Add(fid, keyType, key, key, metadataType, metadata);
    //     vm.prank(to);
    //     keyRegistry.add(keyType, key, metadataType, metadata);

    //     assertAdded(fid, key, keyType);
    // }     


    //////////////////////////////////////////////////
    // HELPERS
    //////////////////////////////////////////////////       

    /*
    *
    * ID REGISTRY
    *
    */        

    /* EOA STUFF */

    function _signRegister(
        uint256 pk,
        address to,
        address recovery,
        uint256 deadline
    ) internal returns (bytes memory signature) {
        address signer = vm.addr(pk);
        bytes32 digest = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), to, recovery, idRegistry.nonces(signer), deadline))
        );
        signature = _sign(pk, digest);
    }         

    function _prepareEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
        );        
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
        bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
        SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
        bytes memory encodedWrapper = abi.encode(wrapper);
        return encodedWrapper;                
    }        


    function _prepareEoa6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            idRegistryRegisterForHash,
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

    /* PASSKEY STUFF */

    function _preparePasskeySigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, address recovery, uint256 deadline) public view returns (bytes memory) {
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
        );        
        bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
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


    function _preparePasskey6492SigForSmartWallet(Account memory _initialSigner, bytes[] memory _initialOwners, address recovery, uint256 deadline)
        public
        returns (address, bytes memory)
    {
        // this gets deterministic smart account address from factory
        CoinbaseSmartWallet undeployedLocalAcct =
            CoinbaseSmartWallet(payable(smartWalletFactory.getAddress(_initialOwners, 0)));

        // this creates the hash that will be generated inside of id registry run time
        bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
            keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(undeployedLocalAcct), recovery, idRegistry.nonces(address(undeployedLocalAcct)), deadline))
        );               
        // this creates the hash that will be generated inside of smart account run time
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedLocalAcct,
            idRegistryRegisterForHash,
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

    /*
    *
    * KEY REGISTRY
    *
    */            

    // function _prepareAddKeyEoaSigForSmartWallet(CoinbaseSmartWallet _smartWallet, Account memory eoaOwner, uint256 deadline) public view returns (bytes memory) {
    //     // bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //     //     keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     // );        

    //     // set up signed key request validator metadata signature


    //     bytes32 idRegistryRegisterForHash = idRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(idRegistry.REGISTER_TYPEHASH(), address(_smartWallet), recovery, idRegistry.nonces(address(_smartWallet)), deadline))
    //     );        
    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    //     bytes memory encodedWrapper = abi.encode(wrapper);



    //     SignedKeyRequestValidator.SignedKeyRequestMetadata memory metadata = SignedKeyRequestValidator({
    //         requestRid: 1,
    //         requestSigner: address(_smartWallet),
    //         signature: ,
    //         deadline: deadline
    //     })

    //     // set up key registry signature


    //     bytes32 keyRegistryAddForHash = keyRegistry.hashTypedDataV4(
    //         keccak256(abi.encode(
    //             keyRegistry.ADD_TYPEHASH(), // typehash
    //             address(_smartWallet),      // rid woner
    //             1,                          // key type
    //             keccak256(EDDSA_PUB_KEY),   // key hash
    //             1,                          // key metadata type
    //             idRegistry.nonces(address(_smartWallet)), 
    //             deadline
    //         )
    //     )
    //     );                


    //     bytes32 smartWalletSafeHash = _smartWallet.replaySafeHash(idRegistryRegisterForHash);
    //     bytes memory eoaSig = _sign(eoaOwner.key, smartWalletSafeHash);
    //     SignatureWrapper memory wrapper = SignatureWrapper({ownerIndex: 0, signatureData: eoaSig});
    //     bytes memory encodedWrapper = abi.encode(wrapper);
    //     return encodedWrapper;                
    // }     


}
